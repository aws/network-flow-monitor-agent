#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT, TC_ACT_OK},
    macros::{classifier, sock_ops, map},
    maps::HashMap,
    programs::{TcContext, SockOpsContext},
    bindings::{
        BPF_SOCK_OPS_TCP_CONNECT_CB,
        BPF_SOCK_OPS_STATE_CB,

        BPF_SOCK_OPS_STATE_CB_FLAG,

        bpf_sock_ops,

    },
    helpers::{
        bpf_get_socket_cookie,
        bpf_get_prandom_u32,
        bpf_ktime_get_ns,
    },
    EbpfContext,
};
use aya_log_ebpf::info;
use aya_log_ebpf::WriteToBuf;
use aya_log_ebpf::macro_support::DefaultFormatter;
use aya_log_common::Argument;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
};
use tcp_tester_common::{FlowKey, SocketKey, Direction, FlowConfig, DelayConditioner, DropPacketConditioner, Selector, Conditioner};
use core::num::{NonZeroUsize, TryFromIntError};


// "documentation" on map race conditions if not using BPF_F_NO_PREALLOC
// https://lore.kernel.org/lkml/CAG48ez1-WZH55+Wa2vgwZY_hpZJfnDxMzxGLtuN1hG1z6hKf5Q@mail.gmail.com/T/
// Using BPF_F_NO_PREALLOC will be faster and more consistent in terms of memory, but is not protected
// by RCU.
//
// See more documentation on bpf maps updates here:
// - https://docs.kernel.org/bpf/maps.html
// - https://docs.kernel.org/bpf/map_hash.html
//

// To use BPF_F_LOCK, need a `struct bpf_spin_lock` entry in the value struct.
// In more modern kernels see `btf_parse_fields`.
/* find 'struct bpf_spin_lock' in map value.
 * return >= 0 offset if found
 * and < 0 in case of error
int btf_find_spin_lock(const struct btf *btf, const struct btf_type *t)
*/

#[repr(C)]
struct FlowState {
    start_seq: u32,
    config: FlowConfig,
}

// atomic updates to values in map
// https://reviews.llvm.org/D72184
#[map]
static FLOW_CONFIG: HashMap<FlowKey, FlowState> = HashMap::with_max_entries(1024, 0);
#[map]
static SOCKET_CONFIG: HashMap<SocketKey, FlowConfig> = HashMap::with_max_entries(1024, 0);

#[derive(Debug, PartialEq, Clone, Copy)]
#[allow(non_camel_case_types)]
enum TcpState {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT = 2,
    TCP_SYN_RECV = 3,
    TCP_FIN_WAIT1 = 4,
    TCP_FIN_WAIT2 = 5,
    TCP_TIME_WAIT = 6,
    TCP_CLOSE = 7,
    TCP_CLOSE_WAIT = 8,
    TCP_LAST_ACK = 9,
    TCP_LISTEN = 10,
    TCP_CLOSING = 11,
    TCP_NEW_SYN_RECV = 12,
}

impl TcpState {

    fn from(val: u32) -> Option<Self> {
        match val {
            1 => Some(TcpState::TCP_ESTABLISHED),
            2 => Some(TcpState::TCP_SYN_SENT),
            3 => Some(TcpState::TCP_SYN_RECV),
            4 => Some(TcpState::TCP_FIN_WAIT1),
            5 => Some(TcpState::TCP_FIN_WAIT2),
            6 => Some(TcpState::TCP_TIME_WAIT),
            7 => Some(TcpState::TCP_CLOSE),
            8 => Some(TcpState::TCP_CLOSE_WAIT),
            9 => Some(TcpState::TCP_LAST_ACK),
            10 => Some(TcpState::TCP_LISTEN),
            11 => Some(TcpState::TCP_CLOSING),
            12 => Some(TcpState::TCP_NEW_SYN_RECV),
            _ => None,
        }
    }
}

impl WriteToBuf for &TcpState {
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        let state_str = match self {
            TcpState::TCP_ESTABLISHED => "TCP_ESTABLISHED",
            TcpState::TCP_SYN_SENT => "TCP_SYN_SENT",
            TcpState::TCP_SYN_RECV => "TCP_SYN_RECV",
            TcpState::TCP_FIN_WAIT1 => "TCP_FIN_WAIT1",
            TcpState::TCP_FIN_WAIT2 => "TCP_FIN_WAIT2",
            TcpState::TCP_TIME_WAIT => "TCP_TIME_WAIT",
            TcpState::TCP_CLOSE => "TCP_CLOSE",
            TcpState::TCP_CLOSE_WAIT => "TCP_CLOSE_WAIT",
            TcpState::TCP_LAST_ACK => "TCP_LAST_ACK",
            TcpState::TCP_LISTEN => "TCP_LISTEN",
            TcpState::TCP_CLOSING => "TCP_CLOSING",
            TcpState::TCP_NEW_SYN_RECV => "TCP_NEW_SYN_RECV",
        };

        let wire_len: u16 = match state_str.len().try_into() {
            Ok(wire_len) => Some(wire_len),
            Err(TryFromIntError { .. }) => None,
        }?;
        let mut size = 0;
        macro_rules! copy_from_slice {
            ($value:expr) => {{
                let buf = buf.get_mut(size..(size + $value.len()))?;
                buf.copy_from_slice($value);
                size += $value.len();
            }};
        }

        let tag = Argument::Str.into();

        copy_from_slice!(&[tag]);
        copy_from_slice!(&wire_len.to_ne_bytes());
        copy_from_slice!(state_str.as_bytes());
        NonZeroUsize::new(size)
    }
}

impl WriteToBuf for TcpState {
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        WriteToBuf::write(&self, buf)
    }
}

impl DefaultFormatter for &TcpState {}


#[classifier]
pub fn tcp_tester_tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn get_socket_config(key: SocketKey) -> Option<&'static FlowConfig> {
    unsafe { SOCKET_CONFIG.get(&key) }
}

fn get_socket_key(ctx: &SockOpsContext, direction: Direction) -> SocketKey {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr())};
    SocketKey::new(cookie, direction)
}

fn get_flow_key(ctx: &SockOpsContext) -> FlowKey {
    FlowKey {
        sip: u32::from_be(ctx.local_ip4()),
        dip: u32::from_be(ctx.remote_ip4()),
        sport: ctx.local_port(),
        dport: u32::from_be(ctx.remote_port()),
    }
}

#[sock_ops]
pub fn tcp_tester_sockops(ctx: SockOpsContext) -> u32 {
    match handle_sockops(ctx) {
        Some(val) => {
            val
        }
        None => {
            0
        }
    }
}

fn handle_sockops(ctx: SockOpsContext) -> Option<u32> {
    match ctx.op() {
        BPF_SOCK_OPS_TCP_CONNECT_CB => {
            let _ = ctx.set_cb_flags((BPF_SOCK_OPS_STATE_CB_FLAG | ctx.cb_flags()) as i32);

            let ingress_socket_key = get_socket_key(&ctx, Direction::INGRESS);
            let egress_socket_key = ingress_socket_key.reverse();

            let egress_key = get_flow_key(&ctx);
            let ingress_key = egress_key.reverse();

            let sock_ops: *mut bpf_sock_ops = ctx.as_ptr() as *mut bpf_sock_ops;
            // let state = unsafe { (*sock_ops).state };
            let nxt_seq = unsafe { (*sock_ops).snd_nxt };

            if let Some(config) = get_socket_config(egress_socket_key) {
                let state = FlowState {
                    config: config.clone(),
                    start_seq: 0
                };

                let _ = FLOW_CONFIG.insert(&egress_key, &state, 0);
                // we don't need the socket/cookie config anymore
                let _ = SOCKET_CONFIG.remove(&egress_socket_key);
            };

            if let Some(config) = get_socket_config(ingress_socket_key) {
                let state = FlowState {
                    config: config.clone(),
                    start_seq: 0
                };

                let _ = FLOW_CONFIG.insert(&ingress_key, &state, 0);
                // we don't need the socket/cookie config anymore
                let _ = SOCKET_CONFIG.remove(&ingress_socket_key);
            };
        },
        BPF_SOCK_OPS_STATE_CB => {
            let old = ctx.arg(0);
            let new = ctx.arg(1);

            let sock_ops: *mut bpf_sock_ops = ctx.as_ptr() as *mut bpf_sock_ops;
            // let state = unsafe { (*sock_ops).state };
            let nxt_seq = unsafe { (*sock_ops).snd_nxt };

            let old_state = TcpState::from(old)?;
            let new_state = TcpState::from(new)?;
            info!(&ctx, "old: {}, new: {}, seq: {}", &old_state, &new_state, nxt_seq);

            if new_state == TcpState::TCP_CLOSE {
                let egress_key = get_flow_key(&ctx);
                let ingress_key = egress_key.reverse();

                // the socket is close, remove any config we have.
                let _ = FLOW_CONFIG.remove(&ingress_key);
                let _ = FLOW_CONFIG.remove(&egress_key);
            }
        },
        _ => {

        }
    };

    Some(0)
}

fn get_config(key: FlowKey) -> Option<*mut FlowState> {
    FLOW_CONFIG.get_ptr_mut(&key)
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    // TODO: consider getting flow fields from `ctx.skbuff`, rather than parsing, if possible.
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let sip = u32::from_be(ipv4hdr.src_addr);
    let dip = u32::from_be(ipv4hdr.dst_addr);

    match ipv4hdr.proto {
        IpProto::Tcp => {}
        _ => return Ok(TC_ACT_PIPE),
    }
    let tcphdr: TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;

    let sport = u16::from_be(tcphdr.source);
    let dport = u16::from_be(tcphdr.dest);

    let key = FlowKey {
        sip,
        dip,
        sport: sport.into(),
        dport: dport.into(),
    };

    let action = if let Some(state) = get_config(key) {
        let tcp_seq = u32::from_be(tcphdr.seq);
        let start_seq = unsafe { &mut (*state).start_seq };

        // Store the first sequence number we see so we can reference an offset from that.
        if (*start_seq) == 0 {
            *start_seq = tcp_seq;
        }
        let seq_offset = tcp_seq - *start_seq;

        info!(&ctx, "have config {:i} {:i} {} {}, seq: {}, tcpseq: {}", key.sip, key.dip, key.sport, key.dport, seq_offset, tcp_seq);

        let conditioner = unsafe { &mut (*state).config.conditioner };
        match conditioner {
            Conditioner::Classify(classify) => {
                unsafe { (*ctx.skb.skb).tc_classid = classify.classid };
                TC_ACT_PIPE
            },
            Conditioner::DropPacket(drop) => {
                info!(&ctx, "drop.count: {}", drop.count);

                if drop.count > 0 {
                    drop.count -= 1;
                    info!(&ctx, "after drop.count: {}", drop.count);
                    TC_ACT_SHOT
                } else {
                    TC_ACT_PIPE
                }
            },
            // This at least works with the fq scheduler:
            // https://man7.org/linux/man-pages/man8/tc-fq.8.html
            // https://github.com/torvalds/linux/commit/f11216b24219ab26d8d159fbfa12dff886b16e32
            //
            // The `tstamp` value is in nanoseconds with an absolute offset.
            Conditioner::Delay(delay) => {
                let ts = unsafe { bpf_ktime_get_ns() };

                // there is no floating point support in bpf, so we need to avoid using to get a proportion
                // of the jitter configuration.
                let jitter = ((unsafe { bpf_get_prandom_u32() } % 1000) as u64 * delay.jitter) / 1000;

                let tstamp = ts + delay.offset + (jitter) as u64;

                unsafe { (*ctx.skb.skb).tstamp = tstamp };
                TC_ACT_PIPE
            }
        }
    } else {
        TC_ACT_PIPE
    };

    info!(&ctx, "DEST {:i}, ACTION {}", sip, action);

    Ok(action)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
  unsafe { core::hint::unreachable_unchecked() }
}
