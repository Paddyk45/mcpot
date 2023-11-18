use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct ConfigBind {
    pub addr: String,
    pub port: u16,
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
pub struct Config {
    pub bind: ConfigBind,
    pub server: ConfigServer,
    pub player: Option<Vec<ConfigPlayer>>,
}

impl Config {
    pub fn read(path: String) -> color_eyre::Result<Self> {
        let file = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&file)?)
    }
}
