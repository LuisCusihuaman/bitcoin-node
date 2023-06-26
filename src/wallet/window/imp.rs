use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread;

use glib::subclass::InitializingObject;
use gtk::{ColumnView, ColumnViewColumn, CompositeTemplate, Entry, gio, glib, ListView, NoSelection};
use gtk::gio::Settings;
use gtk::glib::{Continue, MainContext, PRIORITY_DEFAULT, PropertyGet, Sender, StaticType};
use gtk::glib::once_cell::unsync::OnceCell;
use gtk::subclass::prelude::*;
use gtk::traits::RecentManagerExt;

use app::config::Config;
use app::logger::Logger;
use app::net::message::{MessagePayload, TxStatus};
use app::utils::array_to_hex;
use app::wallet::wallet::{User, Wallet};

use crate::transaction_object::TransactionObject;

pub enum MessageWallet {
    UpdateTransactions,
    NewPendingTransaction(String, String),
    GetBalance,
}

// ANCHOR: struct_and_subclass
// Object holding the state
#[derive(CompositeTemplate, Default)]
#[template(resource = "/org/gtk_rs/wallet-rustica/window.ui")]
pub struct Window {
    #[template_child]
    pub available_balance_value: TemplateChild<gtk::Label>,
    #[template_child]
    pub pending_balance_value: TemplateChild<gtk::Label>,
    #[template_child]
    pub total_balance_value: TemplateChild<gtk::Label>,
    #[template_child]
    pub pay_to_entry: TemplateChild<Entry>,
    #[template_child]
    pub amount_entry: TemplateChild<Entry>,
    #[template_child]
    pub balance_section: TemplateChild<gtk::Box>,
    #[template_child]
    pub send_transaction_section: TemplateChild<gtk::Box>,
    #[template_child]
    pub transactions_section: TemplateChild<gtk::Box>,
    #[template_child]
    pub balance_section_button: TemplateChild<gtk::Button>,
    #[template_child]
    pub send_transaction_section_button: TemplateChild<gtk::Button>,
    #[template_child]
    pub transactions_section_button: TemplateChild<gtk::Button>,
    #[template_child]
    pub send_transaction_button: TemplateChild<gtk::Button>,
    #[template_child]
    pub transactions_view: TemplateChild<ColumnView>,
    #[template_child]
    pub tx_id_column: TemplateChild<ColumnViewColumn>,
    #[template_child]
    pub tx_status_column: TemplateChild<ColumnViewColumn>,
    #[template_child]
    pub address_column: TemplateChild<ColumnViewColumn>,
    #[template_child]
    pub amount_column: TemplateChild<ColumnViewColumn>,
    pub transactions: RefCell<Option<gio::ListStore>>,
}

// The central trait for subclassing a GObject
#[glib::object_subclass]
impl ObjectSubclass for Window {
    // `NAME` needs to match `class` attribute of template
    const NAME: &'static str = "TodoWindow";
    type Type = super::Window;
    type ParentType = gtk::ApplicationWindow;

    fn class_init(klass: &mut Self::Class) {
        klass.bind_template();
    }

    fn instance_init(obj: &InitializingObject<Self>) {
        obj.init_template();
    }
}
// ANCHOR_END: struct_and_subclass

// ANCHOR: constructed
// Trait shared by all GObjects
impl ObjectImpl for Window {
    fn constructed(&self) {
        // Call "constructed" on parent
        self.parent_constructed();
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let priv_key_wif = "cSM1NQcoCMDP8jy2AMQWHXTLc9d4HjSr7H4AqxKk2bD1ykbaRw59".to_string();
        let messi = User::new("Messi".to_string(), priv_key_wif, false);
        let wallet = Arc::new(Mutex::new(Wallet::new(config, logger.tx, messi)));
        let wallet_clone = wallet.clone(); // Clone the Arc<Mutex<Wallet>>

        let (sender, receiver) = MainContext::channel(PRIORITY_DEFAULT);
        let sender_clone: Sender<MessageWallet> = sender.clone();

        // Setup
        let obj = self.obj();
        obj.setup_transactions(sender_clone.clone());
        obj.setup_callbacks(sender.clone());
        obj.setup_factories(sender_clone);
        thread::spawn(move || {
            loop {
                let mut wallet = wallet_clone.lock().unwrap();
                wallet.update_txs_history();
                wallet.receive();
                println!("Updating receiving!!");
                drop(wallet);
                thread::sleep(std::time::Duration::from_secs(5));
            }
        });

        let transaction_list_clone = self.transactions.clone();
        receiver.attach(None, move |msg| match msg {
            MessageWallet::UpdateTransactions => {
                println!("Updating transactions");
                let mut wallet = wallet.lock().unwrap();
                transaction_list_clone.borrow().as_ref().unwrap().remove_all();
                for (tx_id, tx_history) in wallet.tnxs_history.iter() {
                    let tx_id_str = array_to_hex(tx_id);
                    let status = match tx_history.1 {
                        TxStatus::Unconfirmed => "Unconfirmed",
                        TxStatus::Confirmed => "Confirmed",
                        TxStatus::Unknown => "Unknown",
                    };
                    let tx_obj = TransactionObject::new(
                        tx_id_str,
                        status.to_string(),
                        tx_history.2.to_string(),
                        tx_history.3.to_string(),
                    );
                    transaction_list_clone.borrow().as_ref().unwrap().append(&tx_obj);
                }
                Continue(true)
            }
            MessageWallet::NewPendingTransaction(address, amount) => {
                let sender_clone = sender.clone();
                let wallet_clone = wallet.clone();
                thread::spawn(move || {
                    let address_clone = address.clone();
                    let mut wallet = wallet_clone.lock().unwrap();
                    wallet.create_pending_tx(address_clone, amount.parse::<f64>().unwrap());
                    println!("New Pending transaction: {} {}", address, amount);
                    sender_clone.send(MessageWallet::UpdateTransactions).unwrap();
                });
                Continue(true)
            }
            MessageWallet::GetBalance => {
                let wallet_clone = wallet.clone();
                let sender_clone = sender.clone();
                thread::spawn(move || {
                    let mut wallet = wallet_clone.lock().unwrap();
                    sender_clone.send(MessageWallet::UpdateTransactions).unwrap();
                });
                Continue(true)
            }
        });
    }
}
// WALLETGTK ->
// ANCHOR_END: constructed

// Trait shared by all widgets
impl WidgetImpl for Window {}

// Trait shared by all windows
impl WindowImpl for Window {}

// Trait shared by all application windows
impl ApplicationWindowImpl for Window {}
