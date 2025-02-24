// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_ret_code::BPF_OK,
    macros::sock_ops,
    programs::SockOpsContext,
};

use nfm_common::{BpfControlConveyor, TcpSockOpsHandler, nfm_now_us};

// The eBPF entry point.
#[sock_ops]
pub fn nfm_sock_ops(ctx: SockOpsContext) -> u32 {
    // We check whether to handle the event as early as possible, to minimize CPU cycles when
    // discarding events.
    let conveyor = BpfControlConveyor{};
    if conveyor.should_handle_event(ctx.op()) {
        let _result_code = TcpSockOpsHandler::new(&ctx, nfm_now_us()).handle_socket_event();
    }

    // Always return ok so as not to mess with the customer connection.
    BPF_OK
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 11] = *b"Apache-2.0\0";
    
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
