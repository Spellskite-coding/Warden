#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::Array,
    programs::TracePointContext,
};

#[map]
static EXEC_COUNT: Array<u64> = Array::with_max_entries(1, 0);

#[tracepoint]
pub fn warden_exec(_ctx: TracePointContext) -> u32 {
    if let Some(count) = EXEC_COUNT.get_ptr_mut(0) {
        unsafe { *count += 1 };
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
