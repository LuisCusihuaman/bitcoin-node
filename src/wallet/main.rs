mod task_object;
mod task_row;
mod window;

use gtk::prelude::*;
use gtk::{gio, glib, Application};
use window::Window;

const APP_ID: &str = "org.gtk_rs.wallet-rustica";

fn main() -> glib::ExitCode {
    // Register and include resources
    gio::resources_register_include!("wallet-rustica.gresource")
        .expect("Failed to register resources.");

    // Create a new application
    let app = Application::builder()
        .application_id(APP_ID)
        .build();

    app.connect_startup(setup_shortcuts);
    app.connect_activate(build_ui);

    // Run the application
    app.run()
}

fn build_ui(app: &Application) {
    // Create a new custom window and show it
    let window = Window::new(app);
    window.present();
}
// ANCHOR_END: main
fn setup_shortcuts(app: &Application) {
    app.set_accels_for_action("win.filter('All')", &["<Ctrl>a"]);
    app.set_accels_for_action("win.filter('Open')", &["<Ctrl>o"]);
    app.set_accels_for_action("win.filter('Done')", &["<Ctrl>d"]);
}
