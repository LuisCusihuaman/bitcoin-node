use glib::Object;
use gtk::glib;

mod imp;

// ANCHOR: glib_wrapper_and_new
glib::wrapper! {
    pub struct TransactionObject(ObjectSubclass<imp::TransactionObject>);
}

impl TransactionObject {
    pub fn new(address: String, amount: String) -> Self {
        Object::builder()
            .property("address", address)
            .property("amount", amount)
            .build()
    }
}
// ANCHOR_END: glib_wrapper_and_new

// ANCHOR: task_data
#[derive(Default)]
pub struct TransactionData {
    pub address: String,
    pub amount: String,
}
// ANCHOR: task_data
