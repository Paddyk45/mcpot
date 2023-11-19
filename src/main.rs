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

use crate::config::Config;
use crate::log::{log_info, log_info_webhook};

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
                tokio::spawn(async { handler(conn).await });
            }
            Err(why) => {
                eprintln!("I/O Error while accepting client: {why}");
            }
        }
    }
}

async fn handler(stream: TcpStream) -> color_eyre::Result<()> {
    stream.set_nodelay(true).unwrap();
    let peer_addr = stream.peer_addr()?;
    let mut connection: Connection<ServerboundHandshakePacket, ClientboundHandshakePacket> =
        Connection::wrap(stream);
    let ServerboundHandshakePacket::ClientIntention(handshake) =
        connection.read().await.expect("Failed to read packet");
    log_info(format!(
        "Handshake from {peer_addr} -> {}:{}, version={}, intention={:?}",
        handshake.hostname,
        handshake.port,
        handshake.protocol_version,
        handshake.intention
    ));

    match handshake.intention {
        ConnectionProtocol::Status => {
            let mut connection = connection.status();
            while let Ok(packet) = connection.read().await {
                match packet {
                    ServerboundStatusPacket::StatusRequest(_) => {
                        log_info_webhook(format!("Got status request from {peer_addr}"));
                        let mut sample = vec![];
                        for player in CONFIG.clone().player.unwrap_or_default() {
                            sample.push(SamplePlayer {
                                id: player.uuid,
                                name: player.name,
                            });
                        }
                        connection
                            .write(
                                ClientboundStatusResponsePacket {
                                    description: CONFIG.server.description.clone().into(),
                                    favicon: None,
                                    players: Players {
                                        max: CONFIG.server.max_players,
                                        online: CONFIG.server.online_players,
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
                        log_info_webhook(format!("Got ping request from {peer_addr}"));
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
                log_info_webhook(format!(
                    "Got login from {peer_addr}, name={}, uuid={:?}",
                    hi.name,
                    hi.profile_id
                ));
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
    tokio::spawn(async move {
        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        sigterm.recv().await;
        exit(0);
    });

    println!("Listening on :{}", CONFIG.bind.port);
    listener(CONFIG.bind.addr.clone(), CONFIG.bind.port).await;
}
