mod client;
mod ui;

use adw::prelude::*;
use clap::Parser;
use gtk::gio;

const APP_ID: &str = "io.warden.Gui";
const STYLE_CSS: &str = include_str!("../data/style.css");

#[derive(Parser, Debug)]
#[command(name = "warden-gui", about = "Warden EDR - status, history and incident details")]
struct Args {
    /// Jump straight to one incident's detail view (used when launched
    /// from a clicked desktop notification), instead of opening on the
    /// home dashboard.
    #[arg(long)]
    incident: Option<String>,
}

/// Declares Warden's UI as dark to libadwaita's own `AdwStyleManager`,
/// rather than only overriding a handful of raw CSS colors (`window {
/// background-color: ...; color: ...; }`) on top of whatever scheme
/// libadwaita otherwise thinks is active. That mismatch was a real,
/// visible bug: without this, on a system in its default LIGHT scheme,
/// libadwaita still computes every one of its OWN built-in styles - most
/// importantly `.dim-label`/`ActionRow` subtitle text, used throughout
/// this UI for "Mode → ENFORCE", module names, timestamps, and more -
/// against a LIGHT base, landing on a low-opacity near-black. Custom CSS
/// then painted the actual background near-black too, so that
/// already-dark, low-opacity text became almost invisible - confirmed
/// live: "Mode", "ENFORCE", module names were barely legible against the
/// window background. Calling this makes every libadwaita-native color
/// (including the ones `.dim-label` computes) resolve correctly against
/// an ACTUAL dark scheme, so `style.css` only has to layer the Warden
/// brand accents (amber highlights, severity dots, header tint) on top
/// of an already contrast-correct base, not fight it.
fn force_dark_style() {
    adw::StyleManager::default().set_color_scheme(adw::ColorScheme::ForceDark);
}

fn load_css() {
    let provider = gtk::CssProvider::new();
    provider.load_from_data(STYLE_CSS);
    gtk::style_context_add_provider_for_display(
        &gtk::gdk::Display::default().expect("no default display - is a graphical session running?"),
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

fn main() -> gtk::glib::ExitCode {
    let args = Args::parse();

    // NON_UNIQUE: without it, GIO registers this as a single-instance,
    // D-Bus-activatable app - a second `warden-gui --incident <id>`
    // launched while one is already running (the common case: a
    // notification gets clicked while the GUI is already open from
    // earlier) never actually runs its own `main()` at all. GIO instead
    // just sends a bare "activate" to the already-running instance,
    // which re-fires *that* instance's `connect_activate` closure - and
    // that closure captured whatever `--incident` value (or none) the
    // FIRST launch had, not this one's. The net effect, confirmed live:
    // clicking a notification's "View details" reliably raised the
    // existing window but never navigated to the clicked incident.
    // NON_UNIQUE makes every launch (search, a desktop notification
    // click, a second notification click) its own independent process
    // that reads its own real argv, at the cost of possibly having more
    // than one Warden window open at once - a fine trade for "the button
    // does what it says" over a silent no-op.
    let app = adw::Application::builder().application_id(APP_ID).flags(gio::ApplicationFlags::NON_UNIQUE).build();

    app.connect_startup(|_| {
        force_dark_style();
        load_css();
    });

    app.connect_activate(move |app| {
        ui::build_window(app, args.incident.clone());
    });

    app.run_with_args::<&str>(&[])
}
