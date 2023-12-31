use regex::Regex;
use ureq::json;

use crate::CONFIG;

fn strip(msg: impl ToString) -> String {
    let msg = msg.to_string();
    msg.replace("||", "|\u{200b}|")
        .replace("@", "@\u{200b}")
        .replace("#", "#\u{200b}")
        .replace("`", "'")
        .replace("http", "h\u{200b}ttp")
}

fn add_ipinfo_to_ip(msg: impl ToString) -> String {
    let ip_regex = Regex::new("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b").unwrap();
    let msg = msg.to_string();
    let mat = ip_regex.find(&msg).unwrap();
    let ip = mat.as_str();
    msg.replacen(ip, &format!("[{0}](https://ipinfo.io/{0})", ip), 1).to_string()
}

pub fn send(message: &impl ToString) -> color_eyre::Result<()> {
    let cont = strip(message.to_string());
    let cont = add_ipinfo_to_ip(cont.clone());
    if let Some(url) = CONFIG.clone().webhook_url {
        ureq::post(&url).send_json(json!(
            {
                "content": cont
            }
        ))?;
    };
    Ok(())
}
