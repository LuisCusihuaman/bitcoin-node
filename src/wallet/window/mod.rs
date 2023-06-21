use std::fs::File;

use gio::Settings;
use glib::{clone, Object};
use gtk::{
    Application, CustomFilter, FilterListModel, gio, glib, NoSelection,
    SignalListItemFactory,
};
use gtk::{ListItem, prelude::*};
use gtk::subclass::prelude::*;

use crate::APP_ID;
use crate::transaction_object::TransactionObject;
use crate::transaction_row::TransactionRow;

mod imp;

glib::wrapper! {
    pub struct Window(ObjectSubclass<imp::Window>)
        @extends gtk::ApplicationWindow, gtk::Window, gtk::Widget,
        @implements gio::ActionGroup, gio::ActionMap, gtk::Accessible, gtk::Buildable,
                    gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;
}

impl Window {
    pub fn new(app: &Application) -> Self {
        // Create new window
        Object::builder().property("application", app).build()
    }
    // ANCHOR: tasks
    fn transactions(&self) -> gio::ListStore {
        // Get state
        self.imp()
            .transactions
            .borrow()
            .clone()
            .expect("Could not get current transactions.")
    }

    // ANCHOR: setup_tasks
    fn setup_transactions(&self) {
        // Create new mode
        let model = gio::ListStore::new(TransactionObject::static_type());

        // Get state and set model
        self.imp().transactions.replace(Some(model)); //transaction: Option<RefCell<gio::ListStore>>,

        // Wrap model with selection and pass it to the list view
        let selection_model = NoSelection::new(Some(self.transactions()));
        self.imp().transactions_view.set_model(Some(&selection_model));
    }
    // ANCHOR_END: setup_tasks
    // ANCHOR: new_transaction
    fn new_transaction(&self) {
        // Get Transaction from entry and clear it
        let buffer_address = self.imp().pay_to_entry.buffer();
        let buffer_amount = self.imp().amount_entry.buffer();
        let address = buffer_address.text().to_string();
        let amount = buffer_amount.text().to_string();
        if address.is_empty() || amount.is_empty() {
            return;
        }
        //clean buffer
        buffer_address.set_text("");
        buffer_amount.set_text("");

        // Add new transaction to model
        let transaction = TransactionObject::new(address, amount);
        self.transactions().append(&transaction); // added to a 'model' store
    }
    // ANCHOR_END: new_task
    // ANCHOR: setup_callbacks
    fn setup_callbacks(&self) {
        self.imp()
            .send_transaction_button
            .connect_clicked(clone!(@weak self as window => move |_| {
                window.new_transaction();
            }));
    }
    // ANCHOR_END: setup_callbacks

    fn setup_factories(&self) {
        // Create a new factory
        let factory_address = SignalListItemFactory::new();

        // Create an empty `TransactionRow` during setup
        //Emitted when a new listitem has been created and needs to be setup for use.
        // It is the first signal emitted for every listitem.
        factory_address.connect_setup(move |_, list_item| {
            // Create `TransactionRow`
            let transaction_row = TransactionRow::new(); //is like a box with a label
            list_item
                .downcast_ref::<ListItem>()
                .expect("Needs to be ListItem")
                .set_child(Some(&transaction_row));
        });

        // Tell factory how to bind `TransactionRow` to a `TransactionObject`
        //Emitted when an object has been bound, for example when a new item has been set on a ListItem and should be bound for use.
        // After this signal was emitted, the object might be shown in a ListView or other widget.
        factory_address.connect_bind(move |_, list_item| {
            // Get `TransactionObject` from `ListItem`
            let transaction_object = list_item
                .downcast_ref::<ListItem>()
                .expect("Needs to be ListItem")
                .item()
                .and_downcast::<TransactionObject>()
                .expect("Needs to be TransactionObject");
            // Get `TransactionRow` from `ListItem`
            let transaction_row = list_item
                .downcast_ref::<ListItem>()
                .expect("Needs to be ListItem")
                .child()
                .and_downcast::<TransactionRow>()
                .expect("The child has to be a `TransactionRow`.");

            transaction_row.bind("address", &transaction_object);
        });

        // Tell factory how to unbind `TransactionRow` from `TransactionObject`
        //Emitted when a object has been unbound from its item, for example when a listitem was removed from use in a list widget and its new item is about to be unset.
        // This signal is the opposite of the bind signal and should be used to undo everything done in that signal.
        factory_address.connect_unbind(move |_, list_item| {
            // Get `TransactionRow` from `ListItem`
            let transaction_row = list_item
                .downcast_ref::<ListItem>()
                .expect("Needs to be ListItem")
                .child()
                .and_downcast::<TransactionRow>()
                .expect("The child has to be a `TransactionRow`.");

            transaction_row.unbind();
        });

        self.imp().address_column.set_factory(Some(&factory_address));

        let factory_amount = SignalListItemFactory::new();

        factory_amount.connect_setup(move |_, list_item| {
            // Create `TransactionRow`
            let transaction_row = TransactionRow::new(); //is like a box with a label
            list_item
                .downcast_ref::<ListItem>()
                .expect("Needs to be ListItem")
                .set_child(Some(&transaction_row));
        });

        factory_amount.connect_bind(move |_, list_item| {
            // Get `TransactionObject` from `ListItem`
            let transaction_object = list_item
                .downcast_ref::<ListItem>()
                .expect("Needs to be ListItem")
                .item()
                .and_downcast::<TransactionObject>()
                .expect("Needs to be TransactionObject");
            // Get `TransactionRow` from `ListItem`
            let transaction_row = list_item
                .downcast_ref::<ListItem>()
                .expect("Needs to be ListItem")
                .child()
                .and_downcast::<TransactionRow>()
                .expect("The child has to be a `TransactionRow`.");

            transaction_row.bind("amount", &transaction_object);
        });

        factory_amount.connect_unbind(move |_, list_item| {
            // Get `TransactionRow` from `ListItem`
            let transaction_row = list_item
                .downcast_ref::<ListItem>()
                .expect("Needs to be ListItem")
                .child()
                .and_downcast::<TransactionRow>()
                .expect("The child has to be a `TransactionRow`.");

            transaction_row.unbind();
        });

        self.imp().amount_column.set_factory(Some(&factory_amount));
    }
}

