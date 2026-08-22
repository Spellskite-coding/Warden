#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_kernel_str_bytes,
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
    EbpfContext as _,
};

/// Matches the sched:sched_process_exec tracepoint format (checked against
/// the running kernel via /sys/kernel/tracing/events/sched/sched_process_exec/format):
/// common header (8 bytes) + __data_loc filename (u32 at offset 8, low 16
/// bits are the byte offset from the record start to the string, high 16
/// bits its length) + pid_t pid (offset 12) + pid_t old_pid (offset 16).
const FILENAME_OFFSET_FIELD: usize = 8;
const PID_FIELD: usize = 12;
const MAX_FILENAME: usize = 128;

#[repr(C)]
pub struct ExecEvent {
    pub pid: i32,
    pub filename: [u8; MAX_FILENAME],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Counts `EVENTS.reserve()` failures (ring buffer full) - one slot per
/// CPU, so a concurrent increment from another CPU can never race this
/// one. Read and logged by userspace: a full ring buffer under a high
/// exec() rate (an attacker can deliberately induce this - a flood of
/// short-lived processes, a controlled fork bomb - to buy a window where
/// this module is dropping events, including the one actually carrying
/// their real payload) previously failed completely silently, with no
/// counter, log, or metric anywhere. This turns that blind spot into an
/// observable signal, even though it can't prevent the drop itself under
/// sustained extreme load.
#[map]
static DROPPED_EVENTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn warden_exec(ctx: TracePointContext) -> u32 {
    match try_warden_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_warden_exec(ctx: TracePointContext) -> Result<u32, u32> {
    let pid: i32 = unsafe { ctx.read_at(PID_FIELD) }.map_err(|_| 1u32)?;
    let data_loc: u32 = unsafe { ctx.read_at(FILENAME_OFFSET_FIELD) }.map_err(|_| 1u32)?;
    let str_offset = (data_loc & 0xFFFF) as usize;

    let mut filename = [0u8; MAX_FILENAME];
    unsafe {
        let src = (ctx.as_ptr() as *const u8).add(str_offset);
        let _ = bpf_probe_read_kernel_str_bytes(src, &mut filename);
    }

    let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) else {
        if let Some(counter) = DROPPED_EVENTS.get_ptr_mut(0) {
            // SAFETY: PerCpuArray guarantees this pointer names the
            // current CPU's own slot, never shared with any other CPU
            // running this same program concurrently - a plain
            // non-atomic increment is race-free here for that reason.
            unsafe { *counter += 1 };
        }
        return Ok(0);
    };
    entry.write(ExecEvent { pid, filename });
    entry.submit(0);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
