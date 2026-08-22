#![no_std]
#![no_main]

use aya_ebpf::{helpers::bpf_get_current_pid_tgid, macros::{map, tracepoint}, maps::{PerCpuArray, RingBuf}, programs::TracePointContext};

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
const SPORT_FIELD: usize = 24;
const DPORT_FIELD: usize = 26;
const FAMILY_FIELD: usize = 28;
const DADDR_FIELD: usize = 36;
const DADDR_V6_FIELD: usize = 56;

/// Both transitions happen synchronously in the initiating syscall's own
/// process context (`connect()` for SYN_SENT, `listen()` for LISTEN), so
/// `bpf_get_current_pid_tgid()` is reliable for both - unlike
/// TCP_ESTABLISHED, often reached asynchronously when a SYN-ACK arrives in
/// a softirq/ksoftirqd context where "current" is not the connecting
/// process at all (a well-known gotcha for this tracepoint, the same
/// reason bcc/bpftrace's own tcpconnect tools hook SYN_SENT, not
/// ESTABLISHED).
const TCP_SYN_SENT: i32 = 2;
const TCP_LISTEN: i32 = 10;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

pub const KIND_CONNECT: u8 = 0;
pub const KIND_LISTEN: u8 = 1;

#[repr(C)]
pub struct ConnectEvent {
    pub pid: i32,
    /// The remote port for a connection attempt, or the local port a
    /// socket started listening on, depending on `kind`.
    pub port: u16,
    pub family: u16,
    pub kind: u8,
    /// Remote address for a connection attempt; unused (all zero) for a
    /// listening socket, which has no single peer. IPv4 left-justified in
    /// the first 4 bytes when family is AF_INET, full 16 bytes used when
    /// AF_INET6.
    pub daddr: [u8; 16],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Counts `EVENTS.reserve()` failures (ring buffer full) - see the
/// identical counter in `warden-exec-ebpf` for the full rationale
/// (silent event loss under a deliberately-induced high connection rate
/// is otherwise a completely invisible blind spot). One slot per CPU:
/// a concurrent increment from another CPU can never race this one.
#[map]
static DROPPED_EVENTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn warden_connect(ctx: TracePointContext) -> u32 {
    match try_warden_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_warden_connect(ctx: TracePointContext) -> Result<u32, u32> {
    let newstate: i32 = unsafe { ctx.read_at(NEWSTATE_FIELD) }.map_err(|_| 1u32)?;
    let kind = match newstate {
        TCP_SYN_SENT => KIND_CONNECT,
        TCP_LISTEN => KIND_LISTEN,
        _ => return Ok(0),
    };

    let family: u16 = unsafe { ctx.read_at(FAMILY_FIELD) }.map_err(|_| 1u32)?;
    let mut daddr = [0u8; 16];
    if kind == KIND_CONNECT {
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
    } else if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    let port: u16 = if kind == KIND_CONNECT {
        unsafe { ctx.read_at(DPORT_FIELD) }.map_err(|_| 1u32)?
    } else {
        unsafe { ctx.read_at(SPORT_FIELD) }.map_err(|_| 1u32)?
    };

    let Some(mut entry) = EVENTS.reserve::<ConnectEvent>(0) else {
        if let Some(counter) = DROPPED_EVENTS.get_ptr_mut(0) {
            // SAFETY: same reasoning as warden-exec-ebpf's identical
            // counter - PerCpuArray guarantees this pointer names only
            // the current CPU's own slot.
            unsafe { *counter += 1 };
        }
        return Ok(0);
    };
    entry.write(ConnectEvent { pid, port, family, kind, daddr });
    entry.submit(0);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
