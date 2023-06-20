use gtk::glib;
use gtk::subclass::prelude::*;

#[derive(Debug, Default, gtk::CompositeTemplate)]
#[template(resource = "/org/gtk_rs/wallet-rustica/grid_cell.ui")]
pub struct GridCell {
    #[template_child]
    pub name: TemplateChild<gtk::Inscription>,
}

#[glib::object_subclass]
impl ObjectSubclass for GridCell {
    const NAME: &'static str = "GridCell";
    type Type = super::GridCell;
    type ParentType = gtk::Widget;

    fn class_init(klass: &mut Self::Class) {
        // When inheriting from GtkWidget directly, you have to either override the size_allocate/measure
        // functions of WidgetImpl trait or use a layout manager which provides those functions for your widgets like below.
        klass.set_layout_manager_type::<gtk::BinLayout>();
        klass.bind_template();
    }

    fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
        obj.init_template();
    }
}

impl ObjectImpl for GridCell {
    fn constructed(&self) {
        self.parent_constructed();
        // Setup
        let obj = self.obj();
        obj.setup_factory();
    }
    fn dispose(&self) {
        self.dispose_template();
    }
}

impl WidgetImpl for GridCell {}
