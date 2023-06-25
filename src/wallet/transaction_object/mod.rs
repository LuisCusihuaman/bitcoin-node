use glib::Object;
use gtk::glib;

mod imp;

// ANCHOR: glib_wrapper_and_new
glib::wrapper! {
    pub struct TransactionObject(ObjectSubclass<imp::TransactionObject>);
}

impl TransactionObject {
    pub fn new(id: String, status: String, receiver_address: String, amount: String) -> Self {
        Object::builder()
            .property("id", id)
            .property("status", status)
            .property("address", receiver_address)
            .property("amount", amount)
            .build()
    }
}
// ANCHOR_END: glib_wrapper_and_new

// ANCHOR: task_data
#[derive(Default)]
pub struct TransactionData {
    pub id: String,
    pub status: String,
    pub address: String,
    pub amount: String,
}
// ANCHOR: task_data
