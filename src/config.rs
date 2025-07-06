use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct ConfigBind {
    pub addr: String,
    pub ports: String, // e.g. "25565,25569,40000-60000"
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
    pub fn read(path: String) -> eyre::Result<Self> {
        let file = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&file)?)
    }

    pub fn util_ports_as_vec(&self) -> eyre::Result<Vec<u16>> {
        let mut v = vec![];
        let ports = self.bind.ports.clone();
        let ports = ports.trim().replace(" ", "");

        for r in ports.split(",") {
            if r.contains("-") {
                let (start, end) = r.split_once("-").unwrap();
                let start = start.parse::<u16>()?;
                let end = end.parse::<u16>()?;

                v.extend(start..=end);
            } else if let Ok(port) = r.parse::<u16>() {
                v.push(port);
            } else {
                eyre::bail!("invalid part");
            }
        }

        Ok(v)
    }
}
