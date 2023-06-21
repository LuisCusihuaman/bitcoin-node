use std::cell::Ref;

use gtk::{gio, glib};
use gtk::glib::BoxedAnyObject;
use gtk::prelude::*;
use gtk::subclass::prelude::*;

mod imp;
glib::wrapper! {
    pub struct GridCell(ObjectSubclass<imp::GridCell>)
        @extends gtk::Widget;
}
struct Row {
    col1: String,
    col2: String,
}

impl Default for GridCell {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Entry {
    pub name: String,
}

impl GridCell {
    pub fn new() -> Self {
        glib::Object::new()
    }

    pub fn set_entry(&self, entry: &Entry) {
        self.imp().name.set_label(&entry.name);
    }
    fn setup_factory(&self) {
        let store = gio::ListStore::new(BoxedAnyObject::static_type());

        (0..10000).for_each(|i| {
            store.append(&BoxedAnyObject::new(Row {
                col1: format!("col1 {i}"),
                col2: format!("col2 {i}"),
            }))
        });
        let sel = gtk::SingleSelection::new(Some(store));
        let columnview = gtk::ColumnView::new(Some(sel));

        let col1factory = gtk::SignalListItemFactory::new();
        let col2factory = gtk::SignalListItemFactory::new();
        col1factory.connect_setup(move |_factory, item| {
            let item = item.downcast_ref::<gtk::ListItem>().unwrap();
            let row = GridCell::new();
            item.set_child(Some(&row));
        });

        col1factory.connect_bind(move |_factory, item| {
            let item = item.downcast_ref::<gtk::ListItem>().unwrap();
            let child = item.child().and_downcast::<GridCell>().unwrap();
            let entry = item.item().and_downcast::<BoxedAnyObject>().unwrap();
            let r: Ref<Row> = entry.borrow();
            let ent = Entry {
                name: r.col1.to_string(),
            };
            child.set_entry(&ent);
        });
        col2factory.connect_setup(move |_factory, item| {
            let item = item.downcast_ref::<gtk::ListItem>().unwrap();
            let row = GridCell::new();
            item.set_child(Some(&row));
        });

        col2factory.connect_bind(move |_factory, item| {
            let item = item.downcast_ref::<gtk::ListItem>().unwrap();
            let child = item.child().and_downcast::<GridCell>().unwrap();
            let entry = item.item().and_downcast::<BoxedAnyObject>().unwrap();
            let r: Ref<Row> = entry.borrow();
            let ent = Entry {
                name: r.col2.to_string(),
            };
            child.set_entry(&ent);
        });
        let col1 = gtk::ColumnViewColumn::new(Some("Column 1"), Some(col1factory));
        let col2 = gtk::ColumnViewColumn::new(Some("Column 2"), Some(col2factory));
        columnview.append_column(&col1);
        columnview.append_column(&col2);

        let scrolled_window = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never) // Disable horizontal scrolling
            .build();

        scrolled_window.set_child(Some(&columnview));
    }
}
