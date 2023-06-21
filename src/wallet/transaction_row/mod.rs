use glib::Object;
use gtk::{glib, pango};
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use pango::{AttrInt, AttrList};

use crate::transaction_object::TransactionObject;

mod imp;

// ANCHOR: glib_wrapper
glib::wrapper! {
    pub struct TransactionRow(ObjectSubclass<imp::TransactionRow>)
    @extends gtk::Box, gtk::Widget,
    @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::Orientable;
}
// ANCHOR_END: glib_wrapper

impl Default for TransactionRow {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionRow {
    pub fn new() -> Self {
        Object::builder().build()
    }
    // ANCHOR: bind
    pub fn bind(&self, transaction_object: &TransactionObject) {
        // Get state
        let content_label = self.imp().content_label.get();
        let mut bindings = self.imp().bindings.borrow_mut();

        // Bind `transaction_object.content` to `transaction_row.content_label.label`
        let content_label_binding = transaction_object
            .bind_property("content", &content_label, "label")
            .sync_create()
            .build();
        // Save binding
        bindings.push(content_label_binding);
    }
    // ANCHOR_END: bind
    // ANCHOR: unbind
    pub fn unbind(&self) {
        // Unbind all stored bindings
        for binding in self.imp().bindings.borrow_mut().drain(..) {
            binding.unbind();
        }
    }
    // ANCHOR_END: unbind
}
