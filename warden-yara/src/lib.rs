mod config;
mod fanotify_monitor;
mod rules;
mod scan;

pub use config::YaraConfig;
pub use fanotify_monitor::run;
pub use scan::{scan_paths, ScanMatch};
