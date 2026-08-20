#![no_std]
#![no_main]

use aya_ebpf::{helpers::bpf_get_current_pid_tgid, macros::{map, tracepoint}, maps::RingBuf, programs::TracePointContext};

/// Matches the sock:inet_sock_set_state tracepoint format (checked against
/// the running kernel via
/// /sys/kernel/tracing/events/sock/inet_sock_set_state/format): common
/// header (8 bytes) + skaddr (8) + oldstate (offset 16) + newstate (offset
/// 20) + sport (offset 24) + dport (offset 26) + family (offset 28) +
/// protocol (offset 30) + saddr[4] (offset 32) + daddr[4] (offset 36) +
/// saddr_v6[16] (offset 40) + daddr_v6[16] (offset 56).
///
/// The tracepoint's own `common_pid` field (offset 4) was tried first and
/// found unreliable by testing: it read back as a nonsensical negative
/// value, and the *same* wrong value for two different real processes -
/// this tracepoint's pid attribution does not behave the way
/// sched_process_exec's does. `bpf_get_current_pid_tgid()`, read directly
/// from the running task instead of the trace record, is the standard fix
/// (the same one bcc/bpftrace's own tcpconnect tools use) and was
/// confirmed correct by testing.
const NEWSTATE_FIELD: usize = 20;
const DPORT_FIELD: usize = 26;
const FAMILY_FIELD: usize = 28;
const DADDR_FIELD: usize = 36;
const DADDR_V6_FIELD: usize = 56;

/// Only the SYN_SENT transition is used, not ESTABLISHED: SYN_SENT happens
/// synchronously inside the connect() syscall, in the calling process's own
/// context, so the tracepoint's pid is reliable. ESTABLISHED is often
/// reached asynchronously when the SYN-ACK arrives, processed in a
/// softirq/ksoftirqd context where the "current pid" is not the process
/// that initiated the connection at all - a well-known gotcha for this
/// tracepoint (the same reason bcc/bpftrace's own tcpconnect tools hook
/// SYN_SENT, not ESTABLISHED).
const TCP_SYN_SENT: i32 = 2;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[repr(C)]
pub struct ConnectEvent {
    pub pid: i32,
    pub dport: u16,
    pub family: u16,
    /// IPv4 address left-justified in the first 4 bytes when family is
    /// AF_INET, full 16 bytes used when AF_INET6.
    pub daddr: [u8; 16],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn warden_connect(ctx: TracePointContext) -> u32 {
    match try_warden_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_warden_connect(ctx: TracePointContext) -> Result<u32, u32> {
    let newstate: i32 = unsafe { ctx.read_at(NEWSTATE_FIELD) }.map_err(|_| 1u32)?;
    if newstate != TCP_SYN_SENT {
        return Ok(0);
    }

    let family: u16 = unsafe { ctx.read_at(FAMILY_FIELD) }.map_err(|_| 1u32)?;
    let mut daddr = [0u8; 16];
    match family {
        AF_INET => {
            let v4: [u8; 4] = unsafe { ctx.read_at(DADDR_FIELD) }.map_err(|_| 1u32)?;
            daddr[..4].copy_from_slice(&v4);
        }
        AF_INET6 => {
            daddr = unsafe { ctx.read_at(DADDR_V6_FIELD) }.map_err(|_| 1u32)?;
        }
        _ => return Ok(0),
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    let dport: u16 = unsafe { ctx.read_at(DPORT_FIELD) }.map_err(|_| 1u32)?;

    let Some(mut entry) = EVENTS.reserve::<ConnectEvent>(0) else {
        return Ok(0);
    };
    entry.write(ConnectEvent { pid, dport, family, daddr });
    entry.submit(0);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
