use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use pico_args;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

mod chacha;
mod chacha_glue;
mod guts;
mod wgobfs;

use crate::wgobfs::MAX_RND_LEN;
use crate::wgobfs::{obfs_udp_payload, unobfs_udp_payload, ForwardState};

const HELP: &str = "\
USAGE:
  rs-wgobfs [OPTIONS]

OPTIONS:
  -h, --help                          Print help information
  -l or --listen <IP:Port>            Listen address:port
  -f or --forward <IP|Hostname:Port>  Peer's address:port
  -s or --secret                      Shared secret
  -m or --mode <obfs|unobfs>          Mode, either obfs or unobfs
";

#[derive(Copy, Clone)]
enum OPMode {
    Obfs,
    UnObfs,
}

struct AppArgs {
    local_addr: SocketAddr,
    fwd_addr: SocketAddr,
    secret: [u8; 32],
    obfs_mode: OPMode,
}

fn parse_socket_addr(s: &str) -> Result<SocketAddr, std::io::Error> {
    // without DNS
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // use DNS
    s.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not resolve address",
        )
    })
}

async fn create_dual_stack_socket(
    addr: SocketAddr,
) -> std::io::Result<UdpSocket> {
    // create a raw socket2 Socket
    let socket: Socket;
    if addr.is_ipv4() {
        socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    } else {
        socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        // disable "IPv6 Only" to allow IPv4 traffic on the same socket
        socket.set_only_v6(false)?;
    }

    socket.bind(&addr.into())?;
    // convert to Tokio UdpSocket
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

fn repeat_string_to_bytes(s: &str, len: usize) -> Vec<u8> {
    let v = s.as_bytes().to_vec();
    let repeat_count = (len + v.len() - 1) / v.len();
    let repeated = v.repeat(repeat_count);
    repeated.into_iter().take(len).collect()
}

fn parse_args() -> Result<AppArgs, pico_args::Error> {
    let mut pargs = pico_args::Arguments::from_env();

    if pargs.contains(["-h", "--help"]) {
        print!("{}", HELP);
        std::process::exit(0);
    }

    let local_str: String = pargs
        .value_from_str("--listen")
        .or_else(|_| pargs.value_from_str("-l"))?;
    let remote_str: String = pargs
        .value_from_str("--forward")
        .or_else(|_| pargs.value_from_str("-f"))?;

    let mode: String = pargs
        .value_from_str("--mode")
        .or_else(|_| pargs.value_from_str("-m"))?;

    let secret: String = pargs
        .value_from_str("--secret")
        .or_else(|_| pargs.value_from_str("-s"))?;

    let secret32 = repeat_string_to_bytes(&secret, 32);
    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(&secret32);

    let args = AppArgs {
        local_addr: parse_socket_addr(&local_str)
            .expect("Failed to parse listening address"),
        fwd_addr: parse_socket_addr(&remote_str)
            .expect("Failed to parse the remote address"),
        secret: secret_arr,
        obfs_mode: match mode.as_str() {
            "obfs" => OPMode::Obfs,
            "unobfs" => OPMode::UnObfs,
            _ => {
                eprintln!("Invalide --mode: {}", mode);
                std::process::exit(1);
            }
        },
    };

    Ok(args)
}

type ClientMap = Arc<RwLock<HashMap<SocketAddr, Client>>>;

struct Client {
    socket: Arc<UdpSocket>,
    handle: JoinHandle<()>,
    last_seen: AtomicU64,
}

impl Drop for Client {
    fn drop(&mut self) {
        // tell the spawned task to stop
        self.handle.abort();
    }
}

struct ClientWorker {
    listen_socket: Arc<UdpSocket>,
    recv_socket: Arc<UdpSocket>,
}

impl ClientWorker {
    async fn run(
        self,
        client_addr: SocketAddr,
        key: [u8; 32],
        obfs_mode: OPMode,
    ) {
        let mut buf = [0u8; 1500];
        loop {
            let n = self.recv_socket.recv(&mut buf).await.unwrap();
            // unobfs and forward response back to the original client
            let mut rnd_len: usize = 0;
            match obfs_mode {
                OPMode::Obfs => {
                    if let ForwardState::XTContinue =
                        unobfs_udp_payload(&mut buf, n, &key, &mut rnd_len)
                    {
                        let _ = self
                            .listen_socket
                            .send_to(&buf[..n - rnd_len], client_addr)
                            .await;
                    }
                }

                OPMode::UnObfs => {
                    if let ForwardState::XTContinue =
                        obfs_udp_payload(&mut buf, n, &key, &mut rnd_len)
                    {
                        let _ = self
                            .listen_socket
                            .send_to(&buf[..n + rnd_len], client_addr)
                            .await;
                    }
                }
            }
        }
    }
}

struct ForwardWorker {
    fwd_socket: Arc<UdpSocket>,
}

impl ForwardWorker {
    async fn run(
        self,
        mut buf: BytesMut,
        len: usize,
        key: [u8; 32],
        obfs_mode: OPMode,
    ) -> std::io::Result<()> {
        let mut rnd_len: usize = 0;
        match obfs_mode {
            OPMode::Obfs => {
                if let ForwardState::XTContinue =
                    obfs_udp_payload(&mut buf, len, &key, &mut rnd_len)
                {
                    self.fwd_socket.send(&buf[..len + rnd_len]).await?;
                }
            }
            OPMode::UnObfs => {
                if let ForwardState::XTContinue =
                    unobfs_udp_payload(&mut buf, len, &key, &mut rnd_len)
                {
                    self.fwd_socket.send(&buf[..len - rnd_len]).await?;
                }
            }
        }

        Ok(())
    }
}

#[inline]
fn epoch_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

async fn clean_inactive_client(registry: ClientMap, timeout: u64) {
    let mut interval = tokio::time::interval(Duration::from_secs(120));
    loop {
        interval.tick().await;
        let mut map_write = registry.write().expect("Write-lock failed");
        // retain() removes items where the closure returns false
        map_write.retain(|addr, client| {
            let last_seen = client.last_seen.load(Ordering::Relaxed);
            let is_alive = (epoch_now() - last_seen) < timeout;
            if !is_alive {
                println!("Removing inactive client: {}", addr);
                client.handle.abort();
            }
            is_alive
        });
    }
}

const SLAB_SIZE: usize = 1024 * 256;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}.", e);
            std::process::exit(1);
        }
    };

    let listener = Arc::new(create_dual_stack_socket(args.local_addr).await?);
    println!("rs-wgobfs, a companion to the Linux kernel module xt_wgobfs");
    println!("  Listening on {}", args.local_addr);
    println!("  Obfuscating and forwarding wireguard to {}", args.fwd_addr);

    let mut global_buf = BytesMut::with_capacity(SLAB_SIZE);
    unsafe {
        global_buf.set_len(SLAB_SIZE);
    }

    let client_map: ClientMap = Arc::new(RwLock::new(HashMap::new()));
    let timeout: u64 = 600;
    tokio::spawn(clean_inactive_client(Arc::clone(&client_map), timeout));
    loop {
        if global_buf.len() < 2048 {
            global_buf = BytesMut::with_capacity(SLAB_SIZE);
            unsafe {
                global_buf.set_len(SLAB_SIZE);
            }
        }

        let (len, client_addr) = listener.recv_from(&mut global_buf).await?;
        // only split_to multiple of 256
        let aligned_len = (len + MAX_RND_LEN + 255) & !255;
        let buf = global_buf.split_to(aligned_len);

        // read lock only lives inside scope
        let mut fwd_socket = {
            let map_read = client_map.read().expect("Read-lock failed");
            match map_read.get(&client_addr) {
                Some(client) => {
                    client.last_seen.store(epoch_now(), Ordering::Relaxed);
                    Some(client.socket.clone())
                }
                None => None,
            }
        };

        // write lock only lives inside scope
        if fwd_socket.is_none() {
            // create a dedicated socket to WG peer for the new client
            let s = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
            s.connect(args.fwd_addr).await?;
            println!("Accepting client {}", client_addr);
            // listen for return traffic from the server to THIS client
            let client_worker = ClientWorker {
                recv_socket: s.clone(),
                listen_socket: listener.clone(),
            };

            // use handle to abort inactive clients
            let handle = tokio::spawn(client_worker.run(
                client_addr,
                args.secret,
                args.obfs_mode,
            ));

            let client = Client {
                socket: s.clone(),
                handle: handle,
                last_seen: AtomicU64::new(epoch_now()), // for cleanup
            };

            let mut map_write = client_map.write().expect("Write-lock failed");
            map_write.insert(client_addr, client);
            fwd_socket = Some(s);
        };

        let fwd_worker = ForwardWorker { fwd_socket: fwd_socket.unwrap() };
        tokio::spawn(fwd_worker.run(buf, len, args.secret, args.obfs_mode));
    }
}
