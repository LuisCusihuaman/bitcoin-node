use std::cell::RefCell;

use glib::{ParamSpec, Properties, Value};
use gtk::glib;
use gtk::prelude::*;
use gtk::subclass::prelude::*;

use super::TransactionData;

// ANCHOR: struct_and_subclass
// Object holding the state
#[derive(Properties, Default)]
#[properties(wrapper_type = super::TransactionObject)]
pub struct TransactionObject {
    #[property(name = "address", get, set, type = String, member = address)]
    #[property(name = "amount", get, set, type = String, member = amount)]
    pub data: RefCell<TransactionData>,
}

// The central trait for subclassing a GObject
#[glib::object_subclass]
impl ObjectSubclass for TransactionObject {
    const NAME: &'static str = "TodoTransactionObject";
    type Type = super::TransactionObject;
}

// Trait shared by all GObjects
impl ObjectImpl for TransactionObject {
    fn properties() -> &'static [ParamSpec] {
        Self::derived_properties()
    }

    fn set_property(&self, id: usize, value: &Value, pspec: &ParamSpec) {
        self.derived_set_property(id, value, pspec)
    }

    fn property(&self, id: usize, pspec: &ParamSpec) -> Value {
        self.derived_property(id, pspec)
    }
}
// ANCHOR_END: struct_and_subclass
