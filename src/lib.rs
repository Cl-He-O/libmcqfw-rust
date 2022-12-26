use std::{net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Result};

use log::{info, warn};

use socks5_proto::{Address, Reply};
use socks5_server::{
    auth::{NoAuth, Password},
    Connection, IncomingConnection, Server as Socks5Server,
};

use regex::bytes::Regex;

use serde::Deserialize;
use tokio::{
    io::{copy, split, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    spawn,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    listen: String,

    username: Option<String>,
    password: Option<String>,

    #[serde(default = "default::split_at")]
    split_at: String,
    #[serde(default = "default::split_step")]
    split_step: usize,

    #[serde(default = "default::http")]
    http: bool,
}

mod default {
    pub fn split_at() -> String {
        r"[\w\d]{2,20}\.\w{2,5}[^.]".into()
    }
    pub fn split_step() -> usize {
        5
    }
    pub fn http() -> bool {
        true
    }
}

pub struct Server {}

impl Server {
    pub fn run(config: Config) -> Result<()> {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(Self::serve(config))
    }

    async fn serve(config: Config) -> Result<()> {
        let listener = TcpListener::bind(config.listen).await?;
        let server = if let (Some(username), Some(password)) = (config.username, config.password) {
            Socks5Server::new(
                listener,
                Arc::new(Password::new(
                    username.as_bytes().to_vec(),
                    password.as_bytes().to_vec(),
                )),
            )
        } else {
            Socks5Server::new(listener, Arc::new(NoAuth))
        };

        let regexs = Arc::new([
            Regex::new(&config.split_at).unwrap(),
            Regex::new(r"^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) ").unwrap(),
            Regex::new(r"\nHost:").unwrap(),
            Regex::new(r" MicroMessenger").unwrap(),
        ]);

        warn!("Listening on {}", server.local_addr().unwrap());

        loop {
            let (conn, from) = server.accept().await?;

            warn!("New connection from {}", from);

            let regexs = regexs.clone();
            spawn(async move {
                if let Err(err) =
                    Self::on_conn(conn, from, regexs, config.http, config.split_step).await
                {
                    warn!("{}", err);
                }
                warn!("Connection closed from {}", from);
            });
        }
    }

    async fn on_conn(
        conn: IncomingConnection,
        from: SocketAddr,
        regexs: Arc<[Regex]>,
        http: bool,
        step: usize,
    ) -> Result<()> {
        const READ_BUF_SIZE: usize = 0x1000;

        match conn.handshake().await? {
            Connection::Connect(connect, addr) => {
                info!("Request accepted");

                let outbound = match addr {
                    Address::SocketAddress(addr) => TcpStream::connect(addr).await,
                    Address::DomainAddress(addr, port) => TcpStream::connect((addr, port)).await,
                };

                if let Ok(outbound) = outbound {
                    info!("Connected to remote");

                    let conn = connect
                        .reply(Reply::Succeeded, Address::unspecified())
                        .await?;

                    let (mut conn_r, mut conn_w) = split(conn);
                    let (mut out_r, mut out_w) = split(outbound);

                    spawn(async move { copy(&mut out_r, &mut conn_w).await });

                    let mut buf = [0; READ_BUF_SIZE];
                    let read_len = conn_r.read(&mut buf).await?;

                    if read_len == 0 {
                        out_w.shutdown().await?;
                        return Err(anyhow!("Unexpected EOF from {}", from));
                    }

                    if http && regexs[1].is_match(&buf[..read_len]) {
                        // keywords capitalization
                        regexs[2..].iter().for_each(|r| {
                            if let Some(range) = r
                                .find(&buf[..read_len])
                                .map_or(None, |mat| Some(mat.range()))
                            {
                                buf[range].make_ascii_uppercase();
                            }
                        });
                    }

                    if let Some(mat) = regexs[0].find(&buf[..read_len]) {
                        // SNI / Hostname
                        out_w.write_all(&buf[..mat.start()]).await?;

                        for i in mat.range().step_by(step) {
                            out_w
                                .write_all(&buf[i..usize::min(i + step, mat.end())])
                                .await?;
                        }

                        out_w.write_all(&buf[mat.end()..read_len]).await?;
                    } else {
                        out_w.write_all(&buf[..read_len]).await?;
                    }

                    copy(&mut conn_r, &mut out_w).await?;
                } else {
                    info!("Host unreachable!");

                    let mut connect = connect
                        .reply(Reply::HostUnreachable, Address::unspecified())
                        .await?;

                    connect.shutdown().await?;
                }
            }
            Connection::Bind(bind, _) => {
                info!("Unsupported command Bind!");

                let mut conn = bind
                    .reply(Reply::CommandNotSupported, Address::unspecified())
                    .await?;

                conn.shutdown().await?;
            }
            Connection::Associate(associate, _) => {
                info!("Unsupported command Associate!");

                let mut conn = associate
                    .reply(Reply::CommandNotSupported, Address::unspecified())
                    .await?;

                conn.shutdown().await?;
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use self::jni::objects::{JClass, JString};
    use self::jni::sys::jstring;
    use self::jni::JNIEnv;
    use super::*;

    #[no_mangle]
    pub extern "C" fn Java_rs_mcqfw_Mcqfw_run(
        env: JNIEnv,
        _: JClass,
        java_config: JString,
    ) -> jstring {
        let config_s = env.get_string(java_config).expect("invalid config string");
        let res =
            if let Err(err) = Server::run(serde_json::from_slice(&config_s.to_bytes()).unwrap()) {
                err.to_string()
            } else {
                "".into()
            };

        env.new_string(&res).unwrap().into_raw()
    }
}
