#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

use std::env;
use std::process::exit;

use azalea_protocol::connect::Connection;
use azalea_protocol::packets::ConnectionProtocol;
use azalea_protocol::packets::handshaking::{
    ClientboundHandshakePacket, ServerboundHandshakePacket,
};
use azalea_protocol::packets::login::clientbound_login_disconnect_packet::ClientboundLoginDisconnectPacket;
use azalea_protocol::packets::login::ServerboundLoginPacket;
use azalea_protocol::packets::status::clientbound_pong_response_packet::ClientboundPongResponsePacket;
use azalea_protocol::packets::status::clientbound_status_response_packet::{
    ClientboundStatusResponsePacket, Players, SamplePlayer, Version,
};
use azalea_protocol::packets::status::ServerboundStatusPacket;
use lazy_static::lazy_static;
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::spawn;
use uuid::Uuid;

use crate::config::Config;
use crate::log::{log_info, log_webhook};

mod config;
mod log;
mod webhook;

lazy_static! {
    static ref CONFIG: Config =
        Config::read(env::var("MCPOT_CONFIG_PATH").unwrap_or_else(|_| "./config.toml".to_string()))
            .expect("Failed to read config");
}

async fn listener(addr: String, port: u16) {
    let listener = TcpListener::bind((addr, port))
        .await
        .expect("Failed to start the listener");
    loop {
        match listener.accept().await {
            Ok((conn, addr)) => {
                log_info(format!("Opening connection to {addr}"));
                tokio::spawn(async move { handler(conn, port).await });
            }
            Err(why) => {
                eprintln!("I/O Error while accepting client: {why}");
            }
        }
    }
}

async fn handler(stream: TcpStream, port: u16) -> color_eyre::Result<()> {
    stream.set_nodelay(true).unwrap();
    let peer_addr = stream.peer_addr()?;
    let mut connection: Connection<ServerboundHandshakePacket, ClientboundHandshakePacket> =
        Connection::wrap(stream);
    let ServerboundHandshakePacket::ClientIntention(handshake) =
        connection.read().await.expect("Failed to read packet");
    log_info(format!(
        "[:{port}] Handshake from {peer_addr} -> {}:{}, version={}, intention={:?}",
        handshake.hostname, handshake.port, handshake.protocol_version, handshake.intention
    ));

    match handshake.intention {
        ConnectionProtocol::Status => {
            let mut connection = connection.status();
            while let Ok(packet) = connection.read().await {
                match packet {
                    ServerboundStatusPacket::StatusRequest(_) => {
                        log_info(format!("[:{port}] Got status request from {peer_addr}"));
                        match CONFIG.webhook.show_host_port {
                            true => {
                                log_webhook(format!(
                                    "Got status request from [{peer_addr}](<https://ipinfo.io/{}>) on port {port}, handshake_host={}, handshake_port={}",
                                    peer_addr.ip(), handshake.hostname, handshake.port
                                ));
                            }
                            false => {
                                log_webhook(format!("Got status request from [{peer_addr}](<https://ipinfo.io/{}>) on port {port}", peer_addr.ip()));
                            }
                        }
                        let mut sample = vec![];
                        for player in CONFIG.clone().player.unwrap_or_default() {
                            sample.push(SamplePlayer {
                                id: player.uuid,
                                name: player.name,
                            });
                        }
                        if CONFIG.randomize.randomize_players {
                            for _ in 0..CONFIG.randomize.randomize_players_len {
                                sample.push(SamplePlayer {
                                    id: Uuid::new_v4().to_string(),
                                    name: random_string::generate(CONFIG.randomize.randomize_players_name_len, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
                                });
                            }
                        }

                        let (online, max) = match CONFIG.randomize.randomize_online_max {
                            true => (fastrand::i32(..), fastrand::i32(..)),
                            false => (CONFIG.server.max_players, CONFIG.server.online_players),
                        };

                        connection
                            .write(
                                ClientboundStatusResponsePacket {
                                    description: CONFIG.server.description.clone().into(),
                                    favicon: None,
                                    players: Players {
                                        max,
                                        online,
                                        sample,
                                    },
                                    version: Version {
                                        name: "Paper 1.20.2".to_string(),
                                        protocol: 764,
                                    },
                                    enforces_secure_chat: None,
                                }
                                .get(),
                            )
                            .await?;
                    }

                    ServerboundStatusPacket::PingRequest(pr) => {
                        log_info(format!("[:{port}] Got ping request from {peer_addr}"));
                        match CONFIG.webhook.show_host_port {
                            true => {
                                log_webhook(format!(
                                    "Got ping request from [{peer_addr}](<https://ipinfo.io/{}>) on port {port}, handshake_host={}, handshake_port={}",
                                    peer_addr.ip(), handshake.hostname, handshake.port
                                ));
                            }
                            false => {
                                log_webhook(format!("Got ping request from [{peer_addr}](<https://ipinfo.io/{}>)", peer_addr.ip()));
                            }
                        }
                        connection
                            .write(ClientboundPongResponsePacket { time: pr.time }.get())
                            .await?;
                    }
                }
            }
        }

        ConnectionProtocol::Login => {
            let mut connection = connection.login();
            let packet = connection.read().await?;
            if let ServerboundLoginPacket::Hello(hi) = packet {
                log_info(format!(
                    "[:{port}] Got login request from {peer_addr}, name={}, uuid={}",
                    hi.name, hi.profile_id
                ));
                match CONFIG.webhook.show_host_port {
                    true => {
                        log_webhook(format!(
                            "Got login from [{peer_addr}](<https://ipinfo.io/{}>) on port {port}, handshake_host={}, handshake_port={}, name={}, uuid={}",
                            peer_addr.ip(), handshake.hostname, handshake.port,  hi.name, hi.profile_id
                        ));
                    }
                    false => {
                        log_webhook(format!(
                            "Got login request from [{peer_addr}](<https://ipinfo.io/{}>), name={}, uuid={}",
                            peer_addr.ip(), hi.name, hi.profile_id
                        ));
                    }
                }
            }

            connection
                .write(
                    ClientboundLoginDisconnectPacket {
                        reason: CONFIG.clone().server.disconnect_message.into(),
                    }
                    .get(),
                )
                .await?;
        }

        _ => {}
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    color_eyre::install().unwrap();
    // Probably not the right way
    spawn(async move {
        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        sigterm.recv().await;
        exit(0);
    });
    println!(
        "Listening on port(s) {}",
        CONFIG
            .bind
            .ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<String>>()
            .join(", ")
    );
    for port in CONFIG.bind.ports.clone() {
        spawn(listener(CONFIG.bind.addr.clone(), port));
    }
    loop {}
}
