use std::cell::RefCell;

use glib::Binding;
use gtk::{CheckButton, CompositeTemplate, glib, Label};
use gtk::subclass::prelude::*;

// ANCHOR: struct_and_subclass
// Object holding the state
#[derive(Default, CompositeTemplate)]
#[template(resource = "/org/gtk_rs/wallet-rustica/transaction_row.ui")]
pub struct TransactionRow {
    #[template_child]
    pub content_label: TemplateChild<Label>,
    // Vector holding the bindings to properties of `TransactionObject`
    pub bindings: RefCell<Vec<Binding>>,
}

// The central trait for subclassing a GObject
#[glib::object_subclass]
impl ObjectSubclass for TransactionRow {
    // `NAME` needs to match `class` attribute of template
    const NAME: &'static str = "TodoTransactionRow";
    type Type = super::TransactionRow;
    type ParentType = gtk::Box;

    fn class_init(klass: &mut Self::Class) {
        klass.bind_template();
    }

    fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
        obj.init_template();
    }
}
// ANCHOR_END: struct_and_subclass

// Trait shared by all GObjects
impl ObjectImpl for TransactionRow {}

// Trait shared by all widgets
impl WidgetImpl for TransactionRow {}

// Trait shared by all boxes
impl BoxImpl for TransactionRow {}
