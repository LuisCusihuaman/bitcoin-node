use std::cell::RefCell;

use glib::subclass::InitializingObject;
use gtk::{ColumnView, ColumnViewColumn, CompositeTemplate, Entry, gio, glib, ListView};
use gtk::gio::Settings;
use gtk::glib::once_cell::unsync::OnceCell;
use gtk::subclass::prelude::*;

// ANCHOR: struct_and_subclass
// Object holding the state
#[derive(CompositeTemplate, Default)]
#[template(resource = "/org/gtk_rs/wallet-rustica/window.ui")]
pub struct Window {
    #[template_child]
    pub pay_to_entry: TemplateChild<Entry>,
    #[template_child]
    pub amount_entry: TemplateChild<Entry>,
    #[template_child]
    pub send_transaction_button: TemplateChild<gtk::Button>,
    #[template_child]
    pub transactions_view: TemplateChild<ColumnView>,
    #[template_child]
    pub tx_id_column: TemplateChild<ColumnViewColumn>,
    #[template_child]
    pub tx_status_column: TemplateChild<ColumnViewColumn>,
    #[template_child]
    pub address_column: TemplateChild<ColumnViewColumn>,
    #[template_child]
    pub amount_column: TemplateChild<ColumnViewColumn>,
    pub transactions: RefCell<Option<gio::ListStore>>,
}

// The central trait for subclassing a GObject
#[glib::object_subclass]
impl ObjectSubclass for Window {
    // `NAME` needs to match `class` attribute of template
    const NAME: &'static str = "TodoWindow";
    type Type = super::Window;
    type ParentType = gtk::ApplicationWindow;

    fn class_init(klass: &mut Self::Class) {
        klass.bind_template();
    }

    fn instance_init(obj: &InitializingObject<Self>) {
        obj.init_template();
    }
}
// ANCHOR_END: struct_and_subclass

// ANCHOR: constructed
// Trait shared by all GObjects
impl ObjectImpl for Window {
    fn constructed(&self) {
        // Call "constructed" on parent
        self.parent_constructed();

        // Setup
        let obj = self.obj();
        obj.setup_transactions();
        obj.setup_callbacks();
        obj.setup_factories();
    }
}
// ANCHOR_END: constructed

// Trait shared by all widgets
impl WidgetImpl for Window {}

// Trait shared by all windows
impl WindowImpl for Window {}

// Trait shared by all application windows
impl ApplicationWindowImpl for Window {}
