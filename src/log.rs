use strip_ansi_escapes::strip_str;
use crate::webhook;

pub fn log_info(msg: impl ToString) {
    println!("{}", strip_str(msg.to_string()));
}

pub fn log_info_webhook(msg: impl ToString) {
    if let Err(why) = webhook::send(&msg) {
        eprintln!("Error sending to webhook: {why}");
    }
    log_info(msg)
}
