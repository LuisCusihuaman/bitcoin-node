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

    // // ANCHOR: settings
    fn setup_settings(&self) {
        //     let settings = Settings::new(APP_ID);
        //     self.imp()
        //         .settings
        //         .set(settings)
        //         .expect("`settings` should not be set before calling `setup_settings`.");
    }
    //
    // fn settings(&self) -> &Settings {
    //     self.imp()
    //         .settings
    //         .get()
    //         .expect("`settings` should be set in `setup_settings`.")
    // }
    // // ANCHOR_END: settings
    //
    // fn tasks(&self) -> gio::ListStore {
    //     // Get state
    //     self.imp()
    //         .tasks
    //         .borrow()
    //         .clone()
    //         .expect("Could not get current tasks.")
    // }
    //
    // // ANCHOR: filter
    // fn filter(&self) -> Option<CustomFilter> {
    //     // Get state
    //
    //     // Get filter_state from settings
    //     let settings = self.settings();
    //     let filter_state: String = settings.get("filter");
    //
    //     // Create custom filters
    //     let filter_open = CustomFilter::new(|obj| {
    //         // Get `TaskObject` from `glib::Object`
    //         let task_object = obj
    //             .downcast_ref::<TaskObject>()
    //             .expect("The object needs to be of type `TaskObject`.");
    //
    //         // Only allow completed tasks
    //         !task_object.is_completed()
    //     });
    //     let filter_done = CustomFilter::new(|obj| {
    //         // Get `TaskObject` from `glib::Object`
    //         let task_object = obj
    //             .downcast_ref::<TaskObject>()
    //             .expect("The object needs to be of type `TaskObject`.");
    //
    //         // Only allow done tasks
    //         task_object.is_completed()
    //     });
    //
    //     // Return the correct filter
    //     match filter_state.as_str() {
    //         "All" => None,
    //         "Open" => Some(filter_open),
    //         "Done" => Some(filter_done),
    //         _ => unreachable!(),
    //     }
    // }
    // // ANCHOR_END: filter

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
        // // Create new model
        // let model = gio::ListStore::new(TaskObject::static_type());
        //
        // // Get state and set model
        // self.imp().tasks.replace(Some(model));
        //
        // // Wrap model with filter and selection and pass it to the list view
        // let filter_model = FilterListModel::new(Some(self.tasks()), self.filter());
        // let selection_model = NoSelection::new(Some(filter_model.clone()));
        // self.imp().tasks_list.set_model(Some(&selection_model));
        //
        // // Filter model whenever the value of the key "filter" changes
        // self.settings().connect_changed(
        //     Some("filter"),
        //     clone!(@weak self as window, @weak filter_model => move |_, _| {
        //         filter_model.set_filter(window.filter().as_ref());
        //     }),
        // );
    }
    // ANCHOR_END: setup_tasks
    // ANCHOR: new_transaction
    fn new_transaction(&self) {
        // Get content from entry and clear it
        let buffer = self.imp().pay_to_entry.buffer();
        let content = buffer.text().to_string();
        if content.is_empty() {
            return;
        }
        //clean buffer
        buffer.set_text("");

        // Add new transaction to model
        let transaction = TransactionObject::new(content);
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
        // // Setup callback for activation of the entry
        // self.imp()
        //     .entry
        //     .connect_activate(clone!(@weak self as window => move |_| {
        //         window.new_task();
        //     }));
        //
        // // Setup callback for clicking (and the releasing) the icon of the entry
        // self.imp().entry.connect_icon_release(
        //     clone!(@weak self as window => move |_,_| {
        //         window.new_task();
        //     }),
        // );
    }
    // ANCHOR_END: setup_callbacks

    // fn new_task(&self) {
    //     // Get content from entry and clear it
    //     let buffer = self.imp().entry.buffer();
    //     let content = buffer.text().to_string();
    //     if content.is_empty() {
    //         return;
    //     }
    //     buffer.set_text("");
    //
    //     // Add new task to model
    //     let task = TaskObject::new(false, content);
    //     self.tasks().append(&task);
    // }

    fn setup_factory(&self) {
        // Create a new factory
        let factory = SignalListItemFactory::new();

        // Create an empty `TransactionRow` during setup
        //Emitted when a new listitem has been created and needs to be setup for use.
        // It is the first signal emitted for every listitem.
        factory.connect_setup(move |_, list_item| {
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
        factory.connect_bind(move |_, list_item| {
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
                .expect("The child has to be a `TaskRow`.");

            transaction_row.bind(&transaction_object);
        });

        // Tell factory how to unbind `TransactionRow` from `TransactionObject`
        //Emitted when a object has been unbound from its item, for example when a listitem was removed from use in a list widget and its new item is about to be unset.
        // This signal is the opposite of the bind signal and should be used to undo everything done in that signal.
        factory.connect_unbind(move |_, list_item| {
            // Get `TaskRow` from `ListItem`
            let transaction_row = list_item
                .downcast_ref::<ListItem>()
                .expect("Needs to be ListItem")
                .child()
                .and_downcast::<TransactionRow>()
                .expect("The child has to be a `TaskRow`.");

            transaction_row.unbind();
        });

        self.imp().transactions_list.set_title(Option::from("Address"));
        self.imp().transactions_list.set_factory(Some(&factory));
        // // Create a new factory
        // let factory = SignalListItemFactory::new();
        //
        // // Create an empty `TaskRow` during setup
        // factory.connect_setup(move |_, list_item| {
        //     // Create `TaskRow`
        //     let task_row = TaskRow::new();
        //     list_item
        //         .downcast_ref::<ListItem>()
        //         .expect("Needs to be ListItem")
        //         .set_child(Some(&task_row));
        // });
        //
        // // Tell factory how to bind `TaskRow` to a `TaskObject`
        // factory.connect_bind(move |_, list_item| {
        //     // Get `TaskObject` from `ListItem`
        //     let task_object = list_item
        //         .downcast_ref::<ListItem>()
        //         .expect("Needs to be ListItem")
        //         .item()
        //         .and_downcast::<TaskObject>()
        //         .expect("The item has to be an `TaskObject`.");
        //
        //     // Get `TaskRow` from `ListItem`
        //     let task_row = list_item
        //         .downcast_ref::<ListItem>()
        //         .expect("Needs to be ListItem")
        //         .child()
        //         .and_downcast::<TaskRow>()
        //         .expect("The child has to be a `TaskRow`.");
        //
        //     task_row.bind(&task_object);
        // });
        //
        // // Tell factory how to unbind `TaskRow` from `TaskObject`
        // factory.connect_unbind(move |_, list_item| {
        //     // Get `TaskRow` from `ListItem`
        //     let task_row = list_item
        //         .downcast_ref::<ListItem>()
        //         .expect("Needs to be ListItem")
        //         .child()
        //         .and_downcast::<TaskRow>()
        //         .expect("The child has to be a `TaskRow`.");
        //
        //     task_row.unbind();
        // });
        //
        // // Set the factory of the list view
        //self.imp().transactions_columnview.set_factory(Some(&factory));
    }

    // ANCHOR: setup_actions
    fn setup_actions(&self) {
        // // Create action from key "filter" and add to action group "win"
        // let action_filter = self.settings().create_action("filter");
        // self.add_action(&action_filter);
        //
        // // Create action to remove done tasks and add to action group "win"
        // let action_remove_done_tasks =
        //     gio::SimpleAction::new("remove-done-tasks", None);
        // action_remove_done_tasks.connect_activate(
        //     clone!(@weak self as window => move |_, _| {
        //         let tasks = window.tasks();
        //         let mut position = 0;
        //         while let Some(item) = tasks.item(position) {
        //             // Get `TaskObject` from `glib::Object`
        //             let task_object = item
        //                 .downcast_ref::<TaskObject>()
        //                 .expect("The object needs to be of type `TaskObject`.");
        //
        //             if task_object.is_completed() {
        //                 tasks.remove(position);
        //             } else {
        //                 position += 1;
        //             }
        //         }
        //     }),
        // );
        // self.add_action(&action_remove_done_tasks);
    }
// ANCHOR_END: setup_actions
}
