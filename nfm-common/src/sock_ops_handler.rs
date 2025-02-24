// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::*;

pub type SockOpsResult = Result<(), SockOpsResultCode>;

#[derive(Debug, PartialEq)]
pub enum SockOpsResultCode {
    OperationUnknown,
    ContextInvalid,
    MapInsertionError,
    SetCbFlagsError,
    RttInvalid,
    SampleDiscard,
}

// Convey's the values of user-space control knobs to BPF.
pub struct BpfControlConveyor {
    #[cfg(not(feature = "bpf"))]
    pub mock_ebpf_maps: MockEbpfMaps,
}

impl BpfControlConveyor {
    pub fn should_handle_event(&self, event_cb_id: u32) -> bool {
        if self.is_new_sock_event(event_cb_id) {
            self.should_handle_new_sock()
        } else {
            // Note that we only sample on letting newly connected sockets into the front door.
            // For sockets we're already tracking we don't want to miss any events.
            true
        }
    }

    fn is_new_sock_event(&self, event_cb_id: u32) -> bool {
        matches!(
            event_cb_id,
            BPF_SOCK_OPS_TCP_CONNECT_CB | BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB
        )
    }

    fn should_handle_new_sock(&self) -> bool {
        let control_option = bpf_map_get!(self, NFM_CONTROL, &SINGLETON_KEY);
        if let Some(control_data) = control_option {
            let sampling_interval = control_data.sampling_interval;
            sampling_interval <= 1 || bpf_get_rand_u32!(self) % sampling_interval == 0
        } else {
            true
        }
    }
}

pub struct TcpSockOpsHandler<'a> {
    ctx: &'a SockOpsContext,
    now_us: u64,
    counters: EventCounters,
    composite_key: CpuSockKey,

    #[cfg(not(feature = "bpf"))]
    pub mock_ebpf_maps: Option<&'a mut MockEbpfMaps>,
}

impl<'a> TcpSockOpsHandler<'a> {
    pub fn new(ctx: &'a SockOpsContext, now_us: u64) -> Self {
        TcpSockOpsHandler {
            ctx,
            now_us,
            counters: Default::default(),
            composite_key: Default::default(),

            #[cfg(not(feature = "bpf"))]
            mock_ebpf_maps: None,
        }
    }

    pub fn handle_socket_event(&mut self) -> SockOpsResult {
        self.counters.socket_events += 1;
        self.composite_key.sock_key = nfm_get_sock_cookie(self.ctx);
        self.composite_key.cpu_id = nfm_get_cpu_id();

        let result = match self.ctx.op() {
            BPF_SOCK_OPS_TCP_CONNECT_CB => self.handle_connect(),
            BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => self.handle_passive_established(),
            BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB => Ok(()), // No-op.
            BPF_SOCK_OPS_STATE_CB => self.handle_state_change(),
            BPF_SOCK_OPS_RTT_CB => self.handle_rtt(),
            BPF_SOCK_OPS_RETRANS_CB => self.handle_retransmit(),
            BPF_SOCK_OPS_RTO_CB => self.handle_rto(),
            BPF_SOCK_OPS_PARSE_HDR_OPT_CB => self.handle_bytes_transferred_event(),
            BPF_SOCK_OPS_HDR_OPT_LEN_CB => self.handle_bytes_transferred_event(),
            _ => {
                self.counters.other_events += 1;
                Err(SockOpsResultCode::OperationUnknown)
            }
        };

        // Persist our new counter contributions.
        unsafe {
            match bpf_map_get_ptr_mut!(self, NFM_COUNTERS, &SINGLETON_KEY) {
                Some(persisted_counters) => {
                    (*persisted_counters).add_from(&self.counters);
                }
                None => {
                    let _ = bpf_map_insert!(
                        self,
                        NFM_COUNTERS,
                        &SINGLETON_KEY,
                        &self.counters,
                        BPF_ANY
                    );
                }
            };
        }

        result
    }

    fn handle_connect(&mut self) -> SockOpsResult {
        self.counters.active_connect_events += 1;
        const IS_CLIENT: bool = true;
        self.handle_new_sock(IS_CLIENT)
    }

    fn handle_passive_established(&mut self) -> SockOpsResult {
        self.counters.passive_established_events += 1;
        const IS_CLIENT: bool = false;
        self.handle_new_sock(IS_CLIENT)
    }

    fn handle_new_sock(&mut self, is_client: bool) -> SockOpsResult {
        let sock_context = SockContext::from_sock_ops(self.ctx, is_client);
        if !sock_context.is_valid() {
            self.counters.sockets_invalid += 1;
            return Err(SockOpsResultCode::ContextInvalid);
        }

        let res = bpf_map_insert!(
            self,
            NFM_SK_PROPS,
            &self.composite_key,
            &sock_context,
            BPF_NOEXIST
        );
        if res.is_err() {
            self.counters.map_insertion_errors += 1;
            return Err(SockOpsResultCode::MapInsertionError);
        }

        // Register to receive events only for successfully recorded sockets, meaning after success
        // of the above map insertion.
        self.configure_flags()?;

        match self.get_or_add_sock_stats() {
            Ok(stats_raw) => unsafe {
                let sock_stats = &mut *stats_raw;
                sock_stats.connect_start_us = self.now_us;
                if is_client {
                    sock_stats.connect_attempts += 1;
                }

                if nfm_get_sock_state(self.ctx) == BPF_TCP_ESTABLISHED {
                    sock_stats
                        .state_flags
                        .insert(SockStateFlags::ENTERED_ESTABLISH);
                }
                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    fn handle_state_change(&mut self) -> SockOpsResult {
        self.counters.state_change_events += 1;

        // This callback is called before the state is actually changed, so the arguments need to
        // be used instead of the ctx.state.
        let old_state = self.ctx.arg(0);
        let new_state = self.ctx.arg(1);
        let mut new_flags = SockStateFlags::empty();

        match self.get_or_add_sock_stats() {
            Ok(stats_raw) => unsafe {
                let sock_stats = &mut *stats_raw;

                if new_state == BPF_TCP_ESTABLISHED {
                    new_flags |= SockStateFlags::ENTERED_ESTABLISH;
                    sock_stats.connect_end_us = self.now_us;

                    if old_state == BPF_TCP_SYN_SENT {
                        self.counters.active_established_events += 1;
                        sock_stats.connect_successes += 1;
                    }
                } else if !matches!(new_state, BPF_TCP_SYN_SENT | BPF_TCP_SYN_RECV) {
                    new_flags |= SockStateFlags::STARTED_CLOSURE;

                    if matches!(old_state, BPF_TCP_SYN_SENT | BPF_TCP_SYN_RECV) {
                        new_flags |= SockStateFlags::TERMINATED_FROM_SYN;
                    }

                    if new_state == BPF_TCP_CLOSE {
                        new_flags |= SockStateFlags::CLOSED;

                        // Store some final stats on connection close.
                        let event_stats = nfm_get_sock_ops_stats(self.ctx);
                        sock_stats.bytes_received = event_stats.bytes_received;
                        sock_stats.bytes_delivered = event_stats.bytes_acked;
                        sock_stats.segments_received = event_stats.segments_received;
                        sock_stats.segments_delivered = event_stats.segments_delivered;

                        if old_state == BPF_TCP_ESTABLISHED {
                            new_flags |= SockStateFlags::TERMINATED_FROM_EST;
                        }
                    }
                }

                sock_stats.state_flags.insert(new_flags);
                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    fn handle_rtt(&mut self) -> SockOpsResult {
        self.counters.rtt_events += 1;

        // A recent Linux enhancement [a,b] supplies the most recently measured and smoothed RTT
        // values as arguments to this BPF callback.  If we do not see those, we fallback to a less
        // timely value on the sock-ops struct and increment a counter.
        //
        // [a] https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/commit/?id=48e2cd3e3dcf
        // [b] https://code.amazon.com/reviews/CR-144526532/
        let event_stats = nfm_get_sock_ops_stats(self.ctx);
        let rtt_measured_us = match self.ctx.arg(0) {
            0 => {
                self.counters.rtts_invalid += 1;
                event_stats.srtt_us
            }
            x => x,
        };
        let rtt_smoothed_us = match self.ctx.arg(1) {
            0 => event_stats.srtt_us,
            x => x >> 3,
        };

        match self.get_or_add_sock_stats() {
            Ok(stats_raw) => unsafe {
                let sock_stats = &mut *stats_raw;
                sock_stats.rtt_count += 1;
                sock_stats.rtt_latest_us = rtt_measured_us;
                sock_stats.rtt_smoothed_us = rtt_smoothed_us;

                // Take this opporunity to update bytes transferred as well.
                sock_stats.bytes_received = event_stats.bytes_received;
                sock_stats.bytes_delivered = event_stats.bytes_acked;
                sock_stats.segments_received = event_stats.segments_received;
                sock_stats.segments_delivered = event_stats.segments_delivered;

                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    fn handle_retransmit(&mut self) -> SockOpsResult {
        self.counters.retrans_events += 1;

        // Args are: [seq-num, num-segs, tx-errno].
        let retrans_segments = self.ctx.arg(1);

        match self.get_or_add_sock_stats() {
            Ok(stats_raw) => unsafe {
                let sock_stats = &mut *stats_raw;
                match nfm_get_sock_state(self.ctx) {
                    BPF_TCP_ESTABLISHED => sock_stats.retrans_est += retrans_segments,
                    BPF_TCP_SYN_SENT => {
                        sock_stats.retrans_syn += retrans_segments;
                        sock_stats.connect_attempts += retrans_segments as u8;
                    }
                    BPF_TCP_SYN_RECV => sock_stats.retrans_syn += retrans_segments,
                    _ => sock_stats.retrans_close += retrans_segments,
                };

                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    fn handle_rto(&mut self) -> SockOpsResult {
        self.counters.rto_events += 1;

        match self.get_or_add_sock_stats() {
            Ok(stats_raw) => unsafe {
                let sock_stats = &mut *stats_raw;
                match nfm_get_sock_state(self.ctx) {
                    BPF_TCP_ESTABLISHED => sock_stats.rtos_est += 1,
                    BPF_TCP_SYN_SENT | BPF_TCP_SYN_RECV => sock_stats.rtos_syn += 1,
                    _ => sock_stats.rtos_close += 1,
                };
                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    fn handle_bytes_transferred_event(&mut self) -> SockOpsResult {
        match self.get_or_add_sock_stats() {
            Ok(stats_raw) => unsafe {
                // Update running stats.
                let sock_stats = &mut *stats_raw;
                let event_stats = nfm_get_sock_ops_stats(self.ctx);
                sock_stats.bytes_received = event_stats.bytes_received;
                sock_stats.bytes_delivered = event_stats.bytes_acked;
                sock_stats.segments_received = event_stats.segments_received;
                sock_stats.segments_delivered = event_stats.segments_delivered;
                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    fn get_or_add_sock_stats(&mut self) -> Result<*mut SockStats, SockOpsResultCode> {
        match bpf_map_get_ptr_mut!(self, NFM_SK_STATS, &self.composite_key) {
            Some(stats_raw) => unsafe {
                let sock_stats = &mut *stats_raw;
                sock_stats.last_touched_us = self.now_us;
                Ok(sock_stats)
            },
            None => {
                let new_stats = SockStats {
                    last_touched_us: self.now_us,
                    ..Default::default()
                };
                match bpf_map_insert!(
                    self,
                    NFM_SK_STATS,
                    &self.composite_key,
                    &new_stats,
                    BPF_NOEXIST
                ) {
                    Ok(_) => match bpf_map_get_ptr_mut!(self, NFM_SK_STATS, &self.composite_key) {
                        Some(stats) => Ok(stats),
                        None => {
                            self.counters.map_insertion_errors += 1;
                            Err(SockOpsResultCode::MapInsertionError)
                        }
                    },
                    Err(_) => {
                        self.counters.map_insertion_errors += 1;
                        Err(SockOpsResultCode::MapInsertionError)
                    }
                }
            }
        }
    }

    fn configure_flags(&mut self) -> SockOpsResult {
        // Tell the kernel which events we want to receive for the current socket.
        match self.ctx.set_cb_flags(
            (BPF_SOCK_OPS_RTT_CB_FLAG
                | BPF_SOCK_OPS_RTO_CB_FLAG
                | BPF_SOCK_OPS_STATE_CB_FLAG
                | BPF_SOCK_OPS_RETRANS_CB_FLAG
                | BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG

                // The following provides us with events for non-data egress packets (such as RSTs
                // and dup-ACKs).  Without this, a socket can be evicted before being marked as
                // severed within the flow.
                | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG) as i32,
        ) {
            Ok(_) => Ok(()),
            Err(_code) => {
                self.counters.set_flags_errors += 1;
                Err(SockOpsResultCode::SetCbFlagsError)
            }
        }
    }
}

#[cfg(all(test, not(feature = "bpf")))]
mod test {
    use super::*;

    const NO_COOKIE: u64 = 0;

    fn run_sock_ops_test(
        cookie: u64,
        op_code: u32,
        mock_ebpf_maps: &mut MockEbpfMaps,
        ktime_us: u64,
        expectation: SockOpsResult,
    ) {
        let no_args: [u32; 2] = [0, 0];
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_SYN_SENT,
            op_code,
            no_args,
            mock_ebpf_maps,
            ktime_us,
            expectation,
        );
    }

    fn run_sock_ops_test_with_args(
        cookie: u64,
        sock_state: u32,
        op_code: u32,
        args: [u32; 2],
        mock_ebpf_maps: &mut MockEbpfMaps,
        ktime_us: u64,
        expectation: SockOpsResult,
    ) {
        let ctx = SockOpsContext {
            cookie,
            sock_state,
            op: op_code,
            args,
            family: AF_INET,
            ..Default::default()
        };

        // Handle the event.
        let mut handler = TcpSockOpsHandler::new(&ctx, ktime_us);
        handler.mock_ebpf_maps = Some(mock_ebpf_maps);
        let result = handler.handle_socket_event();

        // Validate initial results.
        assert_eq!(result, expectation);
        if expectation.is_ok() {
            let composite_key = CpuSockKey {
                sock_key: cookie,
                cpu_id: MOCK_CPU_ID,
            };
            assert_eq!(
                mock_ebpf_maps.sock_stats(&composite_key).last_touched_us,
                ktime_us
            );
        }
    }

    #[test]
    fn test_ebpf_op_invalid() {
        let mock_ktime_us: u64 = 0;
        let mut mock_ebpf_maps = MockEbpfMaps::new();
        const INVALID_OP: u32 = 0;
        run_sock_ops_test(
            NO_COOKIE,
            INVALID_OP,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Err(SockOpsResultCode::OperationUnknown),
        );
    }

    #[test]
    fn test_ebpf_op_valid() {
        let mock_ktime_us: u64 = 0;
        let mut mock_ebpf_maps = MockEbpfMaps::new();
        let cookie: u64 = 211;
        run_sock_ops_test(
            cookie,
            BPF_SOCK_OPS_TCP_CONNECT_CB,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );
    }

    #[test]
    fn test_ebpf_context_invalid() {
        // Prep our test data.
        let mock_ktime_us: u64 = 0;
        let mut mock_ebpf_maps = MockEbpfMaps::new();
        const AF_OTHER: u32 = 0;
        let ctx = SockOpsContext {
            op: BPF_SOCK_OPS_TCP_CONNECT_CB,
            family: AF_OTHER,
            ..Default::default()
        };

        // Try to handle the event.
        let mut handler = TcpSockOpsHandler::new(&ctx, mock_ktime_us);
        handler.mock_ebpf_maps = Some(&mut mock_ebpf_maps);
        let result = handler.handle_socket_event();

        // Confirm failure.
        assert_eq!(result, Err(SockOpsResultCode::ContextInvalid));
        assert_eq!(mock_ebpf_maps.counters().active_connect_events, 1);
        assert_eq!(mock_ebpf_maps.counters().sockets_invalid, 1);
        assert!(mock_ebpf_maps.NFM_SK_PROPS.data.is_empty());
        assert!(mock_ebpf_maps.NFM_SK_STATS.data.is_empty());
    }

    #[test]
    fn test_ebpf_sock_op_connect() {
        let mock_ktime_us: u64 = 0;
        let mut mock_ebpf_maps = MockEbpfMaps::new();
        let cookie: u64 = 197;
        run_sock_ops_test(
            cookie,
            BPF_SOCK_OPS_TCP_CONNECT_CB,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        assert_eq!(mock_ebpf_maps.counters().active_connect_events, 1);
        assert_eq!(mock_ebpf_maps.NFM_SK_PROPS.data.len(), 1);
        assert_eq!(mock_ebpf_maps.NFM_SK_STATS.data.len(), 1);
    }

    #[test]
    fn test_ebpf_sock_op_passive_established() {
        let mock_ktime_us: u64 = 0;
        let mut mock_ebpf_maps = MockEbpfMaps::new();
        let cookie: u64 = 197;
        run_sock_ops_test(
            cookie,
            BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        assert_eq!(mock_ebpf_maps.counters().passive_established_events, 1);
        assert_eq!(mock_ebpf_maps.NFM_SK_PROPS.data.len(), 1);
        assert_eq!(mock_ebpf_maps.NFM_SK_STATS.data.len(), 1);
    }

    #[test]
    fn test_ebpf_sock_op_active_established_sans_connect() {
        let mock_ktime_us: u64 = 0;
        let mut mock_ebpf_maps = MockEbpfMaps::new();
        let cookie: u64 = 197;
        let ctx = SockOpsContext {
            op: BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,
            family: AF_INET,
            cookie,
            ..Default::default()
        };

        // Handle the event.
        let mut handler = TcpSockOpsHandler::new(&ctx, mock_ktime_us);
        handler.mock_ebpf_maps = Some(&mut mock_ebpf_maps);
        let result = handler.handle_socket_event();

        // Validate results.
        assert_eq!(result, Ok(()));
        assert_eq!(mock_ebpf_maps.counters().active_established_events, 0);
        assert!(mock_ebpf_maps.NFM_SK_PROPS.data.is_empty());
        assert!(mock_ebpf_maps.NFM_SK_STATS.data.is_empty());
    }

    #[test]
    fn test_ebpf_sock_op_active_established() {
        let mock_ktime_us: u64 = 99;
        let cookie: u64 = 197;
        let mut mock_ebpf_maps = MockEbpfMaps::new();

        // Handle two events.
        run_sock_ops_test(
            cookie,
            BPF_SOCK_OPS_TCP_CONNECT_CB,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_SYN_SENT,
            BPF_SOCK_OPS_STATE_CB,
            [BPF_TCP_SYN_SENT, BPF_TCP_ESTABLISHED],
            &mut mock_ebpf_maps,
            mock_ktime_us + 10,
            Ok(()),
        );

        // Validate results.
        assert_eq!(mock_ebpf_maps.NFM_SK_PROPS.data.len(), 1);
        assert_eq!(mock_ebpf_maps.counters().active_connect_events, 1);

        let composite_key = CpuSockKey {
            sock_key: cookie,
            cpu_id: MOCK_CPU_ID,
        };
        let _ = mock_ebpf_maps.sock_props(&composite_key);
        let sock_stats = mock_ebpf_maps.sock_stats(&composite_key);
        assert_eq!(sock_stats.connect_start_us, mock_ktime_us);
        assert_eq!(sock_stats.connect_end_us, mock_ktime_us + 10);
    }

    #[test]
    fn test_ebpf_sock_op_rtt_with_arg() {
        let mock_ktime_us: u64 = 0;
        let mut mock_ebpf_maps = MockEbpfMaps::new();
        let cookie: u64 = 197;

        // Handle a first event.
        run_sock_ops_test(
            cookie,
            BPF_SOCK_OPS_TCP_CONNECT_CB,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        // Handle a second event.
        let ctx = SockOpsContext {
            cookie,
            op: BPF_SOCK_OPS_RTT_CB,
            args: [52, 59 << 3],
            ..Default::default()
        };
        let mut handler = TcpSockOpsHandler::new(&ctx, mock_ktime_us);
        handler.mock_ebpf_maps = Some(&mut mock_ebpf_maps);
        let result = handler.handle_socket_event();

        // Validate results.
        assert_eq!(result, Ok(()));
        let composite_key = CpuSockKey {
            sock_key: cookie,
            cpu_id: MOCK_CPU_ID,
        };
        let sock_stats = mock_ebpf_maps.sock_stats(&composite_key);
        assert_eq!(sock_stats.rtt_count, 1);
        assert_eq!(sock_stats.rtt_latest_us, 52);
        assert_eq!(sock_stats.rtt_smoothed_us, 59);
        assert_eq!(mock_ebpf_maps.counters().rtt_events, 1);
    }

    #[test]
    fn test_ebpf_sock_op_rtt_no_arg() {
        let mock_ktime_us: u64 = 0;
        let mut mock_ebpf_maps = MockEbpfMaps::new();
        let cookie: u64 = 197;

        // Handle a first event.
        run_sock_ops_test(
            cookie,
            BPF_SOCK_OPS_TCP_CONNECT_CB,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        // Handle a second event.
        let ctx = SockOpsContext {
            cookie,
            op: BPF_SOCK_OPS_RTT_CB,
            args: [0, 0],
            stats: SockOpsStats {
                srtt_us: 59,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut handler = TcpSockOpsHandler::new(&ctx, mock_ktime_us);
        handler.mock_ebpf_maps = Some(&mut mock_ebpf_maps);
        let result = handler.handle_socket_event();

        // Validate results.
        assert_eq!(result, Ok(()));
        let composite_key = CpuSockKey {
            sock_key: cookie,
            cpu_id: MOCK_CPU_ID,
        };
        let sock_stats = mock_ebpf_maps.sock_stats(&composite_key);
        assert_eq!(sock_stats.rtt_count, 1);
        assert_eq!(sock_stats.rtt_latest_us, 59);
        assert_eq!(sock_stats.rtt_smoothed_us, 59);
        assert_eq!(mock_ebpf_maps.counters().rtt_events, 1);
        assert_eq!(mock_ebpf_maps.counters().rtts_invalid, 1);
    }

    #[test]
    fn test_ebpf_sock_op_retrans() {
        let mock_ktime_us: u64 = 0;
        let mut mock_ebpf_maps = MockEbpfMaps::new();
        let cookie: u64 = 197;

        // A connection is initiated, followed by retransmits.
        run_sock_ops_test(
            cookie,
            BPF_SOCK_OPS_TCP_CONNECT_CB,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        let mut num_retrans = 11;
        let args: [u32; 2] = [0, num_retrans];
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_SYN_SENT,
            BPF_SOCK_OPS_RETRANS_CB,
            args,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        // After entering established, more retransmits are seen.  Notice that the new state is
        // reflected in the args, and not the sock context.
        let args: [u32; 2] = [BPF_TCP_SYN_SENT, BPF_TCP_ESTABLISHED];
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_SYN_SENT,
            BPF_SOCK_OPS_STATE_CB,
            args,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        num_retrans = 22;
        let args: [u32; 2] = [0, num_retrans];
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_ESTABLISHED,
            BPF_SOCK_OPS_RETRANS_CB,
            args,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        // Finally, during close, more retransmits are seen.
        let args: [u32; 2] = [BPF_TCP_ESTABLISHED, BPF_TCP_FIN_WAIT1];
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_ESTABLISHED,
            BPF_SOCK_OPS_STATE_CB,
            args,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        num_retrans = 33;
        let args: [u32; 2] = [0, num_retrans];
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_FIN_WAIT1,
            BPF_SOCK_OPS_RETRANS_CB,
            args,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        // Validate results.
        let composite_key = CpuSockKey {
            sock_key: cookie,
            cpu_id: MOCK_CPU_ID,
        };
        let sock_stats = mock_ebpf_maps.sock_stats(&composite_key);
        assert_eq!(sock_stats.retrans_syn, 11);
        assert_eq!(sock_stats.retrans_est, 22);
        assert_eq!(sock_stats.retrans_close, 33);
        assert_eq!(mock_ebpf_maps.counters().retrans_events, 3);
    }

    #[test]
    fn test_ebpf_sock_op_rto() {
        let mock_ktime_us: u64 = 0;
        let mut mock_ebpf_maps = MockEbpfMaps::new();
        let cookie: u64 = 197;

        // A connection is initiated, followed by an RTO.
        run_sock_ops_test(
            cookie,
            BPF_SOCK_OPS_TCP_CONNECT_CB,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );
        run_sock_ops_test(
            cookie,
            BPF_SOCK_OPS_RTO_CB,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        // After entering established, we see another RTO.
        let args: [u32; 2] = [BPF_TCP_SYN_SENT, BPF_TCP_ESTABLISHED];
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_SYN_SENT,
            BPF_SOCK_OPS_STATE_CB,
            args,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_ESTABLISHED,
            BPF_SOCK_OPS_RTO_CB,
            [0, 0],
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        // Finally, during close, another RTO.
        let args: [u32; 2] = [BPF_TCP_ESTABLISHED, BPF_TCP_FIN_WAIT1];
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_ESTABLISHED,
            BPF_SOCK_OPS_STATE_CB,
            args,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_FIN_WAIT1,
            BPF_SOCK_OPS_RTO_CB,
            [0, 0],
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        // Validate results.
        let composite_key = CpuSockKey {
            sock_key: cookie,
            cpu_id: MOCK_CPU_ID,
        };
        let sock_stats = mock_ebpf_maps.sock_stats(&composite_key);
        assert_eq!(sock_stats.rtos_syn, 1);
        assert_eq!(sock_stats.rtos_est, 1);
        assert_eq!(sock_stats.rtos_close, 1);
        assert_eq!(mock_ebpf_maps.counters().rto_events, 3);
    }

    #[test]
    fn test_ebpf_sock_op_rst_on_passive_connect() {
        let mock_ktime_us: u64 = 99;
        let cookie: u64 = 197;
        let mut mock_ebpf_maps = MockEbpfMaps::new();

        // Receive a connection.
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_ESTABLISHED,
            BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
            [0, 0],
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        // Terminate the connect attempt.
        let args: [u32; 2] = [BPF_TCP_ESTABLISHED, BPF_TCP_CLOSE];
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_ESTABLISHED,
            BPF_SOCK_OPS_STATE_CB,
            args,
            &mut mock_ebpf_maps,
            mock_ktime_us + 10,
            Ok(()),
        );

        // Validate results.
        let composite_key = CpuSockKey {
            sock_key: cookie,
            cpu_id: MOCK_CPU_ID,
        };
        let sock_wrap = mock_ebpf_maps.sock_stats(&composite_key);
        assert_eq!(
            sock_wrap.state_flags,
            SockStateFlags::ENTERED_ESTABLISH
                | SockStateFlags::STARTED_CLOSURE
                | SockStateFlags::TERMINATED_FROM_EST
                | SockStateFlags::CLOSED
        );
        assert_eq!(mock_ebpf_maps.counters().state_change_events, 1);
    }

    #[test]
    fn test_ebpf_sock_op_rst_on_active_connect() {
        let mock_ktime_us: u64 = 99;
        let cookie: u64 = 197;
        let mut mock_ebpf_maps = MockEbpfMaps::new();

        // Initiate a connection.
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_SYN_SENT,
            BPF_SOCK_OPS_TCP_CONNECT_CB,
            [0, 0],
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );

        // Terminate the connect attempt.
        let args: [u32; 2] = [BPF_TCP_SYN_SENT, BPF_TCP_CLOSE];
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_SYN_SENT,
            BPF_SOCK_OPS_STATE_CB,
            args,
            &mut mock_ebpf_maps,
            mock_ktime_us + 10,
            Ok(()),
        );

        // Validate results.
        let composite_key = CpuSockKey {
            sock_key: cookie,
            cpu_id: MOCK_CPU_ID,
        };
        let sock_wrap = mock_ebpf_maps.sock_stats(&composite_key);
        assert_eq!(
            sock_wrap.state_flags,
            SockStateFlags::STARTED_CLOSURE
                | SockStateFlags::TERMINATED_FROM_SYN
                | SockStateFlags::CLOSED
        );
        assert_eq!(mock_ebpf_maps.counters().state_change_events, 1);
    }

    #[test]
    fn test_ebpf_sock_op_rst_on_establish() {
        let mock_ktime_us: u64 = 99;
        let cookie: u64 = 197;
        let mut mock_ebpf_maps = MockEbpfMaps::new();

        // Handle two events.
        run_sock_ops_test(
            cookie,
            BPF_SOCK_OPS_TCP_CONNECT_CB,
            &mut mock_ebpf_maps,
            mock_ktime_us,
            Ok(()),
        );
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_SYN_SENT,
            BPF_SOCK_OPS_STATE_CB,
            [BPF_TCP_SYN_SENT, BPF_TCP_ESTABLISHED],
            &mut mock_ebpf_maps,
            mock_ktime_us + 10,
            Ok(()),
        );

        // Handle a 3rd event that mimicks a TCP RST by transitioning from ESTABLISHED to CLOSED.
        let args: [u32; 2] = [BPF_TCP_ESTABLISHED, BPF_TCP_CLOSE];
        run_sock_ops_test_with_args(
            cookie,
            BPF_TCP_ESTABLISHED,
            BPF_SOCK_OPS_STATE_CB,
            args,
            &mut mock_ebpf_maps,
            mock_ktime_us + 10,
            Ok(()),
        );

        // Validate results.
        let composite_key = CpuSockKey {
            sock_key: cookie,
            cpu_id: MOCK_CPU_ID,
        };
        let sock_wrap = mock_ebpf_maps.sock_stats(&composite_key);
        assert_eq!(
            sock_wrap.state_flags,
            SockStateFlags::ENTERED_ESTABLISH
                | SockStateFlags::STARTED_CLOSURE
                | SockStateFlags::TERMINATED_FROM_EST
                | SockStateFlags::CLOSED
        );
        assert_eq!(mock_ebpf_maps.counters().state_change_events, 2);
    }

    #[test]
    fn test_ebpf_sock_op_max_connections() {
        let mut mock_ktime_us: u64 = 99;
        let mut cookie: u64 = 197;
        let mut mock_ebpf_maps = MockEbpfMaps::new();

        let effective_max = MAX_ENTRIES_SK_PROPS_HI.min(MAX_ENTRIES_SK_STATS_HI);
        for _ in 0..effective_max {
            run_sock_ops_test(
                cookie,
                BPF_SOCK_OPS_TCP_CONNECT_CB,
                &mut mock_ebpf_maps,
                mock_ktime_us,
                Ok(()),
            );
            run_sock_ops_test_with_args(
                cookie,
                BPF_TCP_SYN_SENT,
                BPF_SOCK_OPS_STATE_CB,
                [BPF_TCP_SYN_SENT, BPF_TCP_ESTABLISHED],
                &mut mock_ebpf_maps,
                mock_ktime_us + 10,
                Ok(()),
            );

            cookie += 3;
            mock_ktime_us += 10;
        }

        // Validate results.
        assert!(effective_max > 0);
        assert_eq!(
            mock_ebpf_maps.counters().active_connect_events,
            effective_max.try_into().unwrap(),
        );
        assert_eq!(
            mock_ebpf_maps.NFM_SK_PROPS.data.len(),
            effective_max.try_into().unwrap()
        );
        assert_eq!(
            mock_ebpf_maps.NFM_SK_STATS.data.len(),
            effective_max.try_into().unwrap()
        );
    }

    #[test]
    fn test_ebpf_sock_op_too_many_connections() {
        let mut mock_ktime_us: u64 = 99;
        let mut cookie: u64 = 197;
        let mut mock_ebpf_maps = MockEbpfMaps::new();

        for _ in 0..MAX_ENTRIES_SK_PROPS_HI {
            run_sock_ops_test(
                cookie,
                BPF_SOCK_OPS_TCP_CONNECT_CB,
                &mut mock_ebpf_maps,
                mock_ktime_us,
                Ok(()),
            );

            cookie += 3;
            mock_ktime_us += 10;
        }

        for _ in 0..10 {
            run_sock_ops_test(
                cookie,
                BPF_SOCK_OPS_TCP_CONNECT_CB,
                &mut mock_ebpf_maps,
                mock_ktime_us,
                Err(SockOpsResultCode::MapInsertionError),
            );

            cookie += 3;
            mock_ktime_us += 10;
        }

        // Validate results.
        assert!(MAX_ENTRIES_SK_PROPS_HI > 0);
        assert_eq!(
            mock_ebpf_maps.NFM_SK_PROPS.data.len(),
            MAX_ENTRIES_SK_PROPS_HI.try_into().unwrap()
        );
        assert_eq!(
            mock_ebpf_maps.counters().active_connect_events,
            (MAX_ENTRIES_SK_PROPS_HI + 10).try_into().unwrap()
        );
        assert_eq!(mock_ebpf_maps.counters().map_insertion_errors, 10);
    }

    #[test]
    fn test_ebpf_sock_op_too_many_events() {
        let mut mock_ktime_us: u64 = 99;
        let mut cookie: u64 = 197;
        let mut mock_ebpf_maps = MockEbpfMaps::new();

        for _ in 0..MAX_ENTRIES_SK_STATS_HI {
            run_sock_ops_test_with_args(
                cookie,
                BPF_TCP_ESTABLISHED,
                BPF_SOCK_OPS_STATE_CB,
                [BPF_TCP_ESTABLISHED, BPF_TCP_CLOSE],
                &mut mock_ebpf_maps,
                mock_ktime_us,
                Ok(()),
            );

            cookie += 3;
            mock_ktime_us += 10;
        }

        for _ in 0..10 {
            run_sock_ops_test_with_args(
                cookie,
                BPF_TCP_ESTABLISHED,
                BPF_SOCK_OPS_STATE_CB,
                [BPF_TCP_ESTABLISHED, BPF_TCP_CLOSE],
                &mut mock_ebpf_maps,
                mock_ktime_us,
                Err(SockOpsResultCode::MapInsertionError),
            );

            cookie += 3;
            mock_ktime_us += 10;
        }

        // Validate results.
        assert!(MAX_ENTRIES_SK_STATS_HI > 0);
        assert_eq!(
            mock_ebpf_maps.NFM_SK_STATS.data.len(),
            MAX_ENTRIES_SK_STATS_HI.try_into().unwrap()
        );
        assert_eq!(
            mock_ebpf_maps.counters().state_change_events,
            (MAX_ENTRIES_SK_STATS_HI + 10).try_into().unwrap()
        );
        assert_eq!(mock_ebpf_maps.counters().map_insertion_errors, 10);
    }

    #[test]
    fn test_ebpf_sock_op_sample_discard() {
        // A random value not divisible by our sampling interval results in a discard.
        let control_data = ControlData {
            sampling_interval: 2,
            ..Default::default()
        };
        let mut mock_ebpf_maps = MockEbpfMaps::new();
        mock_ebpf_maps.mock_rand = 121;
        mock_ebpf_maps
            .NFM_CONTROL
            .insert(&SINGLETON_KEY, &control_data, BPF_ANY)
            .unwrap();
        let conveyor = BpfControlConveyor { mock_ebpf_maps };

        // We discard new socket events.
        assert!(!conveyor.should_handle_event(BPF_SOCK_OPS_TCP_CONNECT_CB));
        assert!(!conveyor.should_handle_event(BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB));

        // We capture other events.
        assert!(conveyor.should_handle_event(BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB));
        assert!(conveyor.should_handle_event(BPF_SOCK_OPS_RETRANS_CB));
        assert!(conveyor.should_handle_event(BPF_SOCK_OPS_RTT_CB));
        assert!(conveyor.should_handle_event(BPF_SOCK_OPS_RTO_CB));
    }

    #[test]
    fn test_ebpf_sock_op_sample_capture() {
        // A random value that is divisible by our sampling interval results in a capture.
        let control_data = ControlData {
            sampling_interval: 2,
            ..Default::default()
        };
        let mut mock_ebpf_maps = MockEbpfMaps::new();
        mock_ebpf_maps.mock_rand = 122;
        mock_ebpf_maps
            .NFM_CONTROL
            .insert(&SINGLETON_KEY, &control_data, BPF_ANY)
            .unwrap();
        let conveyor = BpfControlConveyor { mock_ebpf_maps };

        // We capture new socket events.
        assert!(conveyor.should_handle_event(BPF_SOCK_OPS_TCP_CONNECT_CB));
        assert!(conveyor.should_handle_event(BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB));

        // We also capture other events.
        assert!(conveyor.should_handle_event(BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB));
        assert!(conveyor.should_handle_event(BPF_SOCK_OPS_RETRANS_CB));
        assert!(conveyor.should_handle_event(BPF_SOCK_OPS_RTT_CB));
        assert!(conveyor.should_handle_event(BPF_SOCK_OPS_RTO_CB));
    }
}
