use aya::maps::Array;
use aya::programs::TracePoint;
use log::info;
use tokio::signal;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/warden-exec")))?;

    let program: &mut TracePoint = ebpf.program_mut("warden_exec").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    info!("probe attached, polling exec count every second (Ctrl-C to exit)");

    let poll = async {
        loop {
            sleep(Duration::from_secs(1)).await;
            let map = ebpf.map("EXEC_COUNT").expect("EXEC_COUNT map missing");
            let array: Array<_, u64> = Array::try_from(map).expect("EXEC_COUNT is not an Array<u64>");
            match array.get(&0, 0) {
                Ok(count) => info!("exec events observed so far: {count}"),
                Err(e) => info!("failed to read EXEC_COUNT: {e}"),
            }
        }
    };

    tokio::select! {
        _ = poll => {}
        _ = signal::ctrl_c() => { info!("exiting"); }
    }
    Ok(())
}
