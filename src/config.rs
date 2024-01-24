use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct ConfigBind {
    pub addr: String,
    pub ports: Vec<u16>,
}

#[derive(Deserialize, Clone)]
pub struct ConfigServer {
    pub disconnect_message: String,
    pub description: String,
    pub online_players: i32,
    pub max_players: i32,
}

#[derive(Deserialize, Clone)]
pub struct ConfigPlayer {
    pub name: String,
    pub uuid: String,
}

#[derive(Deserialize, Clone)]
pub struct ConfigWebhook {
    pub enabled: bool,
    pub url: String,
    pub show_host_port: bool,
}

#[derive(Deserialize, Clone)]
pub struct ConfigRandomize {
    pub randomize_players: bool,
    pub randomize_players_name_len: usize,
    pub randomize_players_len: usize,
    pub randomize_online_max: bool,
}

#[derive(Deserialize, Clone)]
pub struct Config {
    pub bind: ConfigBind,
    pub server: ConfigServer,
    pub webhook: ConfigWebhook,
    pub randomize: ConfigRandomize,
    pub player: Option<Vec<ConfigPlayer>>,
}

impl Config {
    pub fn read(path: String) -> color_eyre::Result<Self> {
        let file = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&file)?)
    }
}
