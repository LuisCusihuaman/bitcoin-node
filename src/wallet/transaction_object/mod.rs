use glib::Object;
use gtk::glib;

mod imp;

// ANCHOR: glib_wrapper_and_new
glib::wrapper! {
    pub struct TransactionObject(ObjectSubclass<imp::TransactionObject>);
}

impl TransactionObject {
    pub fn new(content: String) -> Self {
        Object::builder()
            .property("content", content)
            .build()
    }
}
// ANCHOR_END: glib_wrapper_and_new

// ANCHOR: task_data
#[derive(Default)]
pub struct TaskData {
    pub content: String,
}
// ANCHOR: task_data
