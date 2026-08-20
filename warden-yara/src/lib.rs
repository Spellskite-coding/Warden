mod config;
mod fanotify_monitor;
mod rules;

pub use config::YaraConfig;
pub use fanotify_monitor::run;
