use adw::prelude::*;
use gtk::glib;
use warden_common::control_protocol::StatusInfo;
use warden_common::exceptions::Exception;
use warden_common::history::HistoryRecord;
use warden_common::quarantine::ManifestEntry;

use crate::client;

const LOGO_PATHS: &[&str] = &["/usr/share/warden/logo.png", "/usr/share/icons/hicolor/256x256/apps/warden.png"];

fn brand_header(title: &str) -> adw::HeaderBar {
    let header = adw::HeaderBar::new();

    let title_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    if let Some(path) = LOGO_PATHS.iter().find(|p| std::path::Path::new(p).exists()) {
        let image = gtk::Image::from_file(path);
        image.set_pixel_size(20);
        title_box.append(&image);
    }
    let label = gtk::Label::new(Some(title));
    label.add_css_class("warden-brand-title");
    title_box.append(&label);
    header.set_title_widget(Some(&title_box));

    header
}

fn severity_dot(severity: &str) -> gtk::Box {
    let dot = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    dot.set_size_request(10, 10);
    dot.set_valign(gtk::Align::Center);
    dot.add_css_class("severity-dot");
    dot.add_css_class(&format!("severity-{}", severity.to_lowercase()));
    dot
}

fn format_timestamp(unix_secs: u64) -> String {
    glib::DateTime::from_unix_local(unix_secs as i64).ok().and_then(|dt| dt.format("%Y-%m-%d %H:%M:%S").ok()).map(|s| s.to_string()).unwrap_or_else(|| unix_secs.to_string())
}

fn page(title: &str, header_title: &str, content: &impl IsA<gtk::Widget>) -> adw::NavigationPage {
    let scroller = gtk::ScrolledWindow::new();
    scroller.set_child(Some(content));
    scroller.set_vexpand(true);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&brand_header(header_title));
    toolbar_view.set_content(Some(&scroller));

    adw::NavigationPage::builder().title(title).child(&toolbar_view).build()
}

// ---------- Dashboard ----------

fn build_dashboard_page() -> adw::NavigationPage {
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.set_margin_top(18);
    content.set_margin_bottom(18);
    content.set_margin_start(18);
    content.set_margin_end(18);

    match client::fetch_status() {
        Ok(status) => populate_dashboard(&content, &status),
        Err(e) => {
            let label = gtk::Label::new(Some(&format!("Could not reach the Warden daemon: {e}")));
            label.set_use_markup(false);
            label.add_css_class("warden-empty-state");
            content.append(&label);
        }
    }

    content.append(&build_restart_control());

    page("Dashboard", "Warden", &content)
}

/// A visible, explicit restart action for the whole protection stack
/// (all three `warden`/`warden-exec`/`warden-network` services) - not a
/// per-module restart (see PROGRESS.md: any module failing after startup
/// is already treated as fatal to the whole daemon, so "one module down,
/// others fine" isn't a state that persists in practice). Goes through
/// `pkexec` rather than being a silent one-click action: restarting a
/// security daemon is a privileged, consequential action, and asking for
/// authentication every time is the safer default for a v1.
fn build_restart_control() -> gtk::Box {
    let container = gtk::Box::new(gtk::Orientation::Vertical, 6);
    container.set_margin_top(12);

    let button = gtk::Button::with_label("Restart protection");
    button.set_halign(gtk::Align::Start);
    button.add_css_class("destructive-action");

    let status_label = gtk::Label::new(None);
    status_label.set_use_markup(false);
    status_label.set_xalign(0.0);
    status_label.add_css_class("dim-label");
    status_label.add_css_class("caption");

    {
        let status_label = status_label.clone();
        button.connect_clicked(move |_btn| {
            // .spawn(), not .status(): pkexec blocks on the user
            // authenticating in its own separate prompt, which can take
            // as long as they need - waiting for it here would freeze
            // this window's UI thread for that whole time.
            let result = std::process::Command::new("pkexec")
                .args([SYSTEMCTL_PATH, "restart", "warden.service", "warden-exec.service", "warden-network.service"])
                .spawn();
            match result {
                Ok(_) => status_label.set_text("Restart requested - authenticate in the prompt, then reopen Dashboard to see the new status."),
                Err(e) => status_label.set_text(&format!("Could not run pkexec: {e}")),
            }
        });
    }

    container.append(&button);
    container.append(&status_label);
    container
}

fn populate_dashboard(content: &gtk::Box, status: &StatusInfo) {
    let headline = gtk::Label::new(Some(&format!("Protecting {}", status.target_user)));
    headline.set_use_markup(false);
    headline.set_xalign(0.0);
    headline.add_css_class("title-2");
    content.append(&headline);

    let mode_row = adw::ActionRow::builder().use_markup(false).title("Mode").subtitle(status.mode.to_uppercase()).build();

    let target_mode = if status.mode.eq_ignore_ascii_case("enforce") { "monitor" } else { "enforce" };
    let switch_button = gtk::Button::with_label(&format!("Switch to {}", target_mode.to_uppercase()));
    switch_button.set_valign(gtk::Align::Center);
    switch_button.add_css_class(if target_mode == "enforce" { "destructive-action" } else { "flat" });
    mode_row.add_suffix(&switch_button);

    let mode_status = gtk::Label::new(None);
    mode_status.set_use_markup(false);
    mode_status.set_wrap(true);
    mode_status.set_xalign(0.0);
    mode_status.add_css_class("dim-label");
    mode_status.add_css_class("caption");

    {
        let mode_status = mode_status.clone();
        switch_button.connect_clicked(move |_| {
            run_pkexec_warden(
                &["--set-mode", target_mode],
                &mode_status,
                "Mode change requested - authenticate in the prompt. Protection restarts automatically; refresh in a few seconds to see it applied.",
            );
        });
    }

    let mode_group = adw::PreferencesGroup::new();
    mode_group.add(&mode_row);
    content.append(&mode_group);
    content.append(&mode_status);

    let modules_group = adw::PreferencesGroup::new();
    modules_group.set_title("Modules");
    for m in &status.modules {
        let row = adw::ActionRow::builder().use_markup(false).title(&m.name).build();
        let icon = gtk::Image::from_icon_name(if m.ready { "emblem-ok-symbolic" } else { "dialog-warning-symbolic" });
        icon.add_css_class(if m.ready { "success" } else { "warning" });
        row.add_suffix(&icon);
        row.set_subtitle(if m.ready { "Active" } else { "Not running" });
        modules_group.add(&row);
    }
    content.append(&modules_group);
}

// ---------- Detections ----------

fn build_detail_page(record: &HistoryRecord) -> adw::NavigationPage {
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.set_margin_top(18);
    content.set_margin_bottom(18);
    content.set_margin_start(18);
    content.set_margin_end(18);

    let summary_label = gtk::Label::new(Some(&record.summary));
    summary_label.set_use_markup(false);
    summary_label.set_wrap(true);
    summary_label.set_xalign(0.0);
    summary_label.add_css_class("title-2");
    content.append(&summary_label);

    let badge_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    badge_row.append(&severity_dot(&record.severity));
    let badge_text = gtk::Label::new(Some(&format!("{} · {}", record.module, record.severity)));
    badge_text.set_use_markup(false);
    badge_text.add_css_class("dim-label");
    badge_row.append(&badge_text);
    content.append(&badge_row);

    let group = adw::PreferencesGroup::new();

    let detail_row = adw::ActionRow::builder().use_markup(false).title("Detail").subtitle(&record.detail).build();
    detail_row.set_subtitle_lines(0);
    group.add(&detail_row);

    let time_row = adw::ActionRow::builder().use_markup(false).title("Timestamp").subtitle(format_timestamp(record.timestamp_unix)).build();
    group.add(&time_row);

    let action_row =
        adw::ActionRow::builder().use_markup(false).title("Action taken").subtitle(if record.action_taken { "Yes" } else { "No" }).build();
    group.add(&action_row);

    if let Some(pid) = record.pid {
        let pid_row = adw::ActionRow::builder().use_markup(false).title("Process ID").subtitle(pid.to_string()).build();
        group.add(&pid_row);
    }

    if !record.affected_paths.is_empty() {
        let paths_text = record.affected_paths.join("\n");
        let paths_row = adw::ActionRow::builder().use_markup(false).title("Affected path(s)").subtitle(&paths_text).build();
        paths_row.set_subtitle_lines(0);
        group.add(&paths_row);
    }

    let id_row = adw::ActionRow::builder().use_markup(false).title("Incident ID").subtitle(&record.id).build();
    group.add(&id_row);

    content.append(&group);

    if !record.action_taken && !record.affected_paths.is_empty() {
        let quarantine_status = gtk::Label::new(None);
        quarantine_status.set_use_markup(false);
        quarantine_status.set_wrap(true);
        quarantine_status.set_xalign(0.0);
        quarantine_status.add_css_class("dim-label");
        quarantine_status.add_css_class("caption");

        let quarantine_button = gtk::Button::with_label("Quarantine now");
        quarantine_button.add_css_class("destructive-action");
        quarantine_button.set_halign(gtk::Align::Start);

        let paths = record.affected_paths.clone();
        let status_label = quarantine_status.clone();
        let button = quarantine_button.clone();
        quarantine_button.connect_clicked(move |_| {
            for path in &paths {
                run_pkexec_warden(&["--quarantine-file", path.as_str()], &status_label, "Quarantine requested - authenticate in the prompt, then refresh.");
            }
            button.set_sensitive(false);
        });

        content.append(&quarantine_button);
        content.append(&quarantine_status);
    }

    let scroller = gtk::ScrolledWindow::new();
    scroller.set_child(Some(&content));

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&brand_header("Incident"));
    toolbar_view.set_content(Some(&scroller));

    adw::NavigationPage::builder().title("Incident").child(&toolbar_view).build()
}

fn populate_detection_list(list_box: &gtk::ListBox, records: &[HistoryRecord], nav_view: &adw::NavigationView) {
    while let Some(row) = list_box.row_at_index(0) {
        list_box.remove(&row);
    }

    for record in records.iter().rev() {
        let row = adw::ActionRow::builder()
            .activatable(true)
            .use_markup(false)
            .title(&record.summary)
            .subtitle(format!("{} · {}", record.module, format_timestamp(record.timestamp_unix)))
            .build();
        row.set_title_lines(1);
        row.add_css_class("warden-incident");
        row.add_prefix(&severity_dot(&record.severity));

        // Visible at a glance in the list, not just after opening the
        // detail page - a user reviewing a monitor-mode alert asked
        // "is this actually in quarantine or not?" and the honest answer
        // (report-only, nothing touched) wasn't obvious without digging
        // in, since a "detected" notification looks the same either way.
        let action_badge = gtk::Label::new(Some(if record.action_taken { "Actioned" } else { "Alert only" }));
        action_badge.set_use_markup(false);
        action_badge.add_css_class("caption");
        action_badge.add_css_class(if record.action_taken { "success" } else { "dim-label" });
        row.add_suffix(&action_badge);

        row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));

        let record = record.clone();
        let nav_view = nav_view.clone();
        row.connect_activated(move |_| {
            nav_view.push(&build_detail_page(&record));
        });

        list_box.append(&row);
    }
}

/// Builds the "Detections" top-level page: its own nested `NavigationView`
/// so clicking an incident can still push a detail page, independent of
/// the outer sidebar navigation.
fn build_detections_page() -> (adw::NavigationPage, gtk::ListBox, gtk::Label, adw::NavigationView) {
    let status_label = gtk::Label::new(None);
    status_label.add_css_class("warden-empty-state");
    status_label.set_margin_top(8);
    status_label.set_margin_bottom(8);

    let list_box = gtk::ListBox::new();
    list_box.set_selection_mode(gtk::SelectionMode::None);
    list_box.add_css_class("boxed-list");
    list_box.set_margin_start(12);
    list_box.set_margin_end(12);

    let refresh_button = gtk::Button::from_icon_name("view-refresh-symbolic");
    refresh_button.set_tooltip_text(Some("Refresh"));

    let header = brand_header("Detections");
    header.pack_end(&refresh_button);

    let inner_content = gtk::Box::new(gtk::Orientation::Vertical, 6);
    inner_content.append(&status_label);
    inner_content.append(&list_box);

    let scroller = gtk::ScrolledWindow::new();
    scroller.set_child(Some(&inner_content));
    scroller.set_vexpand(true);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&scroller));

    let root_page = adw::NavigationPage::builder().title("Detections").child(&toolbar_view).build();

    let nav_view = adw::NavigationView::new();
    nav_view.push(&root_page);

    let outer_page = adw::NavigationPage::builder().title("Detections").child(&nav_view).build();

    {
        let list_box = list_box.clone();
        let status_label = status_label.clone();
        let nav_view = nav_view.clone();
        refresh_button.connect_clicked(move |_| {
            refresh_detections(&list_box, &status_label, &nav_view);
        });
    }

    (outer_page, list_box, status_label, nav_view)
}

fn refresh_detections(list_box: &gtk::ListBox, status_label: &gtk::Label, nav_view: &adw::NavigationView) -> Vec<HistoryRecord> {
    match client::fetch_history(200) {
        Ok(records) => {
            status_label.set_text(if records.is_empty() { "No incidents recorded yet." } else { "" });
            populate_detection_list(list_box, &records, nav_view);
            records
        }
        Err(e) => {
            status_label.set_text(&format!("Could not reach the Warden daemon: {e}"));
            populate_detection_list(list_box, &[], nav_view);
            Vec::new()
        }
    }
}

// ---------- Quarantine ----------

fn populate_quarantine_list(list_box: &gtk::ListBox, entries: &[ManifestEntry]) {
    while let Some(row) = list_box.row_at_index(0) {
        list_box.remove(&row);
    }

    for entry in entries {
        let row = adw::ActionRow::builder()
            .use_markup(false)
            .title(&entry.original_path)
            .subtitle(format!("{} · {} · {}", entry.module, format_timestamp(entry.quarantined_at_unix), entry.reason))
            .build();
        row.set_subtitle_lines(2);
        row.add_css_class("warden-incident");

        let restore_button = gtk::Button::with_label("Restore");
        restore_button.set_valign(gtk::Align::Center);
        restore_button.add_css_class("flat");

        let quarantine_name = entry.quarantine_name.clone();
        let row_weak = row.downgrade();
        restore_button.connect_clicked(move |_btn| {
            // Also adds an exception for the restored path (see
            // `warden-core`'s `--restore-quarantine`) - without one it
            // would just get re-quarantined within seconds - so, same
            // reasoning as the Exceptions tab, this goes through pkexec
            // (a real root/admin authentication) rather than the
            // uid-only-gated control socket.
            let result = std::process::Command::new("pkexec").arg(warden_binary_path()).arg("--restore-quarantine").arg(&quarantine_name).spawn();
            if let Some(row) = row_weak.upgrade() {
                match result {
                    Ok(_) => row.set_subtitle("Restore requested - authenticate in the prompt, then refresh."),
                    Err(e) => row.set_subtitle(&format!("Could not run pkexec: {e}")),
                }
            }
        });

        row.add_suffix(&restore_button);
        list_box.append(&row);
    }
}

fn build_quarantine_page() -> (adw::NavigationPage, gtk::ListBox, gtk::Label) {
    let status_label = gtk::Label::new(None);
    status_label.add_css_class("warden-empty-state");
    status_label.set_margin_top(8);
    status_label.set_margin_bottom(8);

    let list_box = gtk::ListBox::new();
    list_box.set_selection_mode(gtk::SelectionMode::None);
    list_box.add_css_class("boxed-list");
    list_box.set_margin_start(12);
    list_box.set_margin_end(12);

    let refresh_button = gtk::Button::from_icon_name("view-refresh-symbolic");
    refresh_button.set_tooltip_text(Some("Refresh"));

    let header = brand_header("Quarantine");
    header.pack_end(&refresh_button);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 6);
    content.append(&status_label);
    content.append(&list_box);

    {
        let list_box = list_box.clone();
        let status_label = status_label.clone();
        refresh_button.connect_clicked(move |_| {
            refresh_quarantine(&list_box, &status_label);
        });
    }

    let scroller = gtk::ScrolledWindow::new();
    scroller.set_child(Some(&content));
    scroller.set_vexpand(true);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&scroller));

    let nav_page = adw::NavigationPage::builder().title("Quarantine").child(&toolbar_view).build();
    (nav_page, list_box, status_label)
}

fn refresh_quarantine(list_box: &gtk::ListBox, status_label: &gtk::Label) {
    match client::fetch_quarantine() {
        Ok(entries) => {
            status_label.set_text(if entries.is_empty() { "Nothing in quarantine." } else { "" });
            populate_quarantine_list(list_box, &entries);
        }
        Err(e) => {
            status_label.set_text(&format!("Could not reach the Warden daemon: {e}"));
            populate_quarantine_list(list_box, &[]);
        }
    }
}

// ---------- Exceptions ----------

/// Runs `pkexec warden --add-exception/--remove-exception <path>`. This
/// is deliberately the ONLY way exceptions are added or removed from the
/// GUI: unlike the control socket (gated only on the connecting uid),
/// pkexec demands a real root/admin authentication every time, so
/// malware already running as the desktop user can't silently whitelist
/// itself through this feature. Listing is still read-only and safe to
/// do directly (see `refresh_exceptions`).
fn run_pkexec_warden(args: &[&str], status_label: &gtk::Label, message_on_launch: &str) {
    match std::process::Command::new("pkexec").arg(warden_binary_path()).args(args).spawn() {
        Ok(_) => status_label.set_text(message_on_launch),
        Err(e) => status_label.set_text(&format!("Could not run pkexec: {e}")),
    }
}

/// The standard, `usr`-merged location of `systemctl` across the whole
/// supported distro matrix - a fixed absolute path, deliberately never a
/// bare `"systemctl"` resolved via `PATH`. `pkexec`, when given a
/// non-absolute command name, resolves it via the CALLING (pre-
/// elevation) process's own `PATH` - so a bare name here would let
/// anything capable of influencing this GUI's `PATH` (a malicious
/// directory prepended via `~/.pam_environment`,
/// `~/.config/environment.d/*.conf`, or the session's inherited
/// environment) get root-executed instead, the next time the user
/// authenticates a routine "Restart protection" click.
const SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";

/// The absolute path to the `warden` binary this GUI was installed
/// alongside (`install.sh` always places both under the same
/// `BIN_DIR`), falling back to a bare name only if that lookup fails -
/// same pattern `warden_common::notify::helper_path` already uses to
/// locate `warden-notify-helper`. Every `pkexec` call site in this file
/// uses this instead of a bare `"warden"` for the same PATH-hijacking
/// reason `SYSTEMCTL_PATH` documents above: `pkexec` resolves a
/// non-absolute command through the pre-elevation caller's own `PATH`.
fn warden_binary_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|dir| dir.join("warden")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("warden"))
}

fn populate_exceptions_list(list_box: &gtk::ListBox, entries: &[Exception], status_label: &gtk::Label) {
    while let Some(row) = list_box.row_at_index(0) {
        list_box.remove(&row);
    }

    for entry in entries {
        let subtitle = match entry {
            Exception::File { sha256, .. } => format!("File - sha256 {}…", sha256.get(..12).unwrap_or(sha256)),
            Exception::Directory { .. } => "Directory - everything underneath is trusted, no integrity check".to_string(),
        };
        let row = adw::ActionRow::builder().use_markup(false).title(entry.path()).subtitle(subtitle).build();
        row.add_css_class("warden-incident");

        let remove_button = gtk::Button::with_label("Remove");
        remove_button.set_valign(gtk::Align::Center);
        remove_button.add_css_class("flat");

        let status_label = status_label.clone();
        let path = entry.path().to_string();
        remove_button.connect_clicked(move |_| {
            run_pkexec_warden(&["--remove-exception", &path], &status_label, "Removal requested - authenticate in the prompt, then refresh.");
        });

        row.add_suffix(&remove_button);
        list_box.append(&row);
    }
}

fn refresh_exceptions(list_box: &gtk::ListBox, status_label: &gtk::Label) {
    // Read-only: exceptions.toml is world-readable, so this talks
    // straight to the file instead of round-tripping through the daemon
    // - there is nothing here a compromised desktop-user process
    // couldn't already read directly itself.
    match warden_common::exceptions::list() {
        Ok(entries) => {
            if entries.is_empty() {
                status_label.set_text("No exceptions configured.");
            } else {
                status_label.set_text("");
            }
            populate_exceptions_list(list_box, &entries, status_label);
        }
        Err(e) => {
            status_label.set_text(&format!("Could not read the exceptions list: {e}"));
            populate_exceptions_list(list_box, &[], status_label);
        }
    }
}

fn build_exceptions_page() -> (adw::NavigationPage, gtk::ListBox, gtk::Label) {
    let status_label = gtk::Label::new(None);
    status_label.set_use_markup(false);
    status_label.add_css_class("warden-empty-state");
    status_label.set_margin_top(8);
    status_label.set_margin_bottom(8);

    let intro = gtk::Label::new(Some(
        "Exempt a path from every detection module. A file is pinned to its current SHA-256, \
         so replacing it invalidates the exception automatically - prefer this whenever you're \
         exempting a single stable binary. A directory trusts everything underneath it with no \
         integrity check, for things like an app install directory that changes on every update. \
         Adding or removing either requires your root/admin password - so malware already running \
         as you can't silently whitelist itself here.",
    ));
    intro.set_use_markup(false);
    intro.set_wrap(true);
    intro.set_xalign(0.0);
    intro.add_css_class("dim-label");
    intro.add_css_class("caption");
    intro.set_margin_start(12);
    intro.set_margin_end(12);
    intro.set_margin_top(8);

    let path_entry = gtk::Entry::new();
    path_entry.set_placeholder_text(Some("/usr/local/bin/some-tool or /opt/some-app/"));
    path_entry.set_hexpand(true);

    let add_button = gtk::Button::with_label("Add exception");
    add_button.add_css_class("suggested-action");

    let entry_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    entry_row.set_margin_start(12);
    entry_row.set_margin_end(12);
    entry_row.set_margin_top(6);
    entry_row.append(&path_entry);
    entry_row.append(&add_button);

    let list_box = gtk::ListBox::new();
    list_box.set_selection_mode(gtk::SelectionMode::None);
    list_box.add_css_class("boxed-list");
    list_box.set_margin_start(12);
    list_box.set_margin_end(12);
    list_box.set_margin_top(6);

    {
        let status_label = status_label.clone();
        let path_entry = path_entry.clone();
        add_button.connect_clicked(move |_| {
            let path = path_entry.text().to_string();
            if path.trim().is_empty() {
                status_label.set_text("Enter a path first.");
                return;
            }
            run_pkexec_warden(&["--add-exception", path.trim()], &status_label, "Exception requested - authenticate in the prompt, then refresh.");
        });
    }

    let refresh_button = gtk::Button::from_icon_name("view-refresh-symbolic");
    refresh_button.set_tooltip_text(Some("Refresh"));
    let header = brand_header("Exceptions");
    header.pack_end(&refresh_button);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.append(&intro);
    content.append(&entry_row);
    content.append(&status_label);
    content.append(&list_box);

    {
        let list_box = list_box.clone();
        let status_label = status_label.clone();
        refresh_button.connect_clicked(move |_| {
            refresh_exceptions(&list_box, &status_label);
        });
    }

    let scroller = gtk::ScrolledWindow::new();
    scroller.set_child(Some(&content));
    scroller.set_vexpand(true);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&scroller));

    let nav_page = adw::NavigationPage::builder().title("Exceptions").child(&toolbar_view).build();
    (nav_page, list_box, status_label)
}

// ---------- Scan ----------

/// Formats a `ScanStatusInfo` for the status label.
fn format_scan_status(status: &warden_common::control_protocol::ScanStatusInfo) -> String {
    if status.running {
        format!("Scanning... {} files checked so far, {} match(es) found.", status.files_scanned, status.matches_found)
    } else if status.files_scanned > 0 {
        format!(
            "Scan complete: {} files checked, {} match(es) found{}.",
            status.files_scanned,
            status.matches_found,
            if status.matches_found > 0 { " - see Detections" } else { "" }
        )
    } else {
        String::new()
    }
}

fn build_scan_page() -> adw::NavigationPage {
    let intro = gtk::Label::new(Some(
        "Audit specific directories for known-malicious files using the same YARA rules as live \
         monitoring. Report-only: nothing found here is touched or quarantined automatically - \
         matches show up in Detections for you to review. Useful right after installing Warden, \
         or any time you just want to check.",
    ));
    intro.set_use_markup(false);
    intro.set_wrap(true);
    intro.set_xalign(0.0);
    intro.add_css_class("dim-label");
    intro.add_css_class("caption");
    intro.set_margin_start(12);
    intro.set_margin_end(12);
    intro.set_margin_top(8);

    let path_entry = gtk::Entry::new();
    path_entry.set_placeholder_text(Some("/home/you/Downloads, /tmp, ..."));
    path_entry.set_hexpand(true);

    let scan_button = gtk::Button::with_label("Start scan");
    scan_button.add_css_class("suggested-action");

    let entry_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    entry_row.set_margin_start(12);
    entry_row.set_margin_end(12);
    entry_row.set_margin_top(6);
    entry_row.append(&path_entry);
    entry_row.append(&scan_button);

    let status_label = gtk::Label::new(None);
    status_label.set_use_markup(false);
    status_label.set_wrap(true);
    status_label.set_xalign(0.0);
    status_label.add_css_class("warden-empty-state");
    status_label.set_margin_start(12);
    status_label.set_margin_end(12);
    status_label.set_margin_top(8);

    {
        let path_entry = path_entry.clone();
        let status_label = status_label.clone();
        scan_button.connect_clicked(move |_| {
            let paths: Vec<String> = path_entry.text().split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            if paths.is_empty() {
                status_label.set_text("Enter at least one path first.");
                return;
            }
            match client::start_scan(paths) {
                Ok(()) => {
                    status_label.set_text("Scan started...");
                    // Polls every 2s until the daemon reports the scan
                    // is no longer running - cheap local socket calls,
                    // and the only way this UI finds out a background
                    // scan finished (the protocol has no push/streaming).
                    let status_label = status_label.clone();
                    glib::timeout_add_seconds_local(2, move || match client::fetch_scan_status() {
                        Ok(status) => {
                            status_label.set_text(&format_scan_status(&status));
                            if status.running { glib::ControlFlow::Continue } else { glib::ControlFlow::Break }
                        }
                        Err(_) => glib::ControlFlow::Break,
                    });
                }
                Err(e) => status_label.set_text(&format!("Could not start scan: {e}")),
            }
        });
    }

    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.append(&intro);
    content.append(&entry_row);
    content.append(&status_label);

    let scroller = gtk::ScrolledWindow::new();
    scroller.set_child(Some(&content));
    scroller.set_vexpand(true);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&brand_header("Scan"));
    toolbar_view.set_content(Some(&scroller));

    adw::NavigationPage::builder().title("Scan").child(&toolbar_view).build()
}

// ---------- Top-level window: sidebar + content ----------

pub fn build_window(app: &adw::Application, jump_to_incident: Option<String>) {
    let window = adw::ApplicationWindow::builder().application(app).title("Warden").default_width(880).default_height(620).build();

    let split_view = adw::NavigationSplitView::new();

    let sidebar_list = gtk::ListBox::new();
    sidebar_list.add_css_class("navigation-sidebar");
    sidebar_list.set_selection_mode(gtk::SelectionMode::Browse);
    for label in ["Dashboard", "Detections", "Quarantine", "Exceptions", "Scan"] {
        let row = adw::ActionRow::builder().use_markup(false).title(label).build();
        sidebar_list.append(&row);
    }

    let sidebar_toolbar = adw::ToolbarView::new();
    sidebar_toolbar.add_top_bar(&brand_header("Warden"));
    sidebar_toolbar.set_content(Some(&sidebar_list));
    let sidebar_page = adw::NavigationPage::builder().title("Warden").child(&sidebar_toolbar).build();
    split_view.set_sidebar(Some(&sidebar_page));

    let (detections_page, detections_list, detections_status, detections_nav) = build_detections_page();
    let (quarantine_page, quarantine_list, quarantine_status) = build_quarantine_page();
    let (exceptions_page, exceptions_list, exceptions_status) = build_exceptions_page();
    let scan_page = build_scan_page();

    let dashboard_page = build_dashboard_page();
    split_view.set_content(Some(&dashboard_page));

    {
        let split_view = split_view.clone();
        let detections_page = detections_page.clone();
        let quarantine_page = quarantine_page.clone();
        let quarantine_list = quarantine_list.clone();
        let quarantine_status = quarantine_status.clone();
        let exceptions_page = exceptions_page.clone();
        let exceptions_list = exceptions_list.clone();
        let exceptions_status = exceptions_status.clone();
        let scan_page = scan_page.clone();
        sidebar_list.connect_row_selected(move |_, row| {
            let Some(row) = row else { return };
            match row.index() {
                0 => split_view.set_content(Some(&build_dashboard_page())),
                1 => split_view.set_content(Some(&detections_page)),
                2 => {
                    refresh_quarantine(&quarantine_list, &quarantine_status);
                    split_view.set_content(Some(&quarantine_page));
                }
                3 => {
                    refresh_exceptions(&exceptions_list, &exceptions_status);
                    split_view.set_content(Some(&exceptions_page));
                }
                4 => split_view.set_content(Some(&scan_page)),
                _ => {}
            }
        });
    }

    window.set_content(Some(&split_view));
    window.present();

    let records = refresh_detections(&detections_list, &detections_status, &detections_nav);

    if let Some(id) = jump_to_incident {
        if let Some(row) = sidebar_list.row_at_index(1) {
            sidebar_list.select_row(Some(&row));
        }
        split_view.set_content(Some(&detections_page));
        if let Some(record) = records.iter().find(|r| r.id == id) {
            detections_nav.push(&build_detail_page(record));
        }
    } else if let Some(row) = sidebar_list.row_at_index(0) {
        sidebar_list.select_row(Some(&row));
    }
}
