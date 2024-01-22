use ureq::json;

use crate::CONFIG;

fn strip(msg: impl ToString) -> String {
    let msg = msg.to_string();
    msg.replace("||", "|\u{200b}|")
        .replace("@", "@\u{200b}")
        .replace("#", "#\u{200b}")
        .replace("`", "\\`")
        .replace("http", "h\u{200b}ttp")
        .replace("*", "\\*")
        .replace("_", "\\_")
        .replace("~", "\\~")
        .replace("discord.", "discord\u{200b}.")
        .replace("h\u{200b}ttps://ipinfo.io/", "https://ipinfo.io/") // Probably not a good idea
}

pub fn send(message: &impl ToString) -> color_eyre::Result<()> {
    let cont = strip(message.to_string());
    if CONFIG.webhook.enabled {
        ureq::post(&CONFIG.webhook.url).send_json(json!(
            {
                "content": cont
            }
        ))?;
    };
    Ok(())
}
