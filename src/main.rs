use pico_args;
use std::net::{SocketAddr, ToSocketAddrs};

use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub use rand_core;
mod chacha;
mod chacha_glue;
mod guts;
mod wgobfs;

use crate::wgobfs::{obfs_udp_payload, unobfs_udp_payload, ForwardState};

const HELP: &str = "\
USAGE:
  rs-wgobfs [OPTIONS]

OPTIONS:
  -h, --help                              Prints help information
  -l or --listen <IP:Port>                Listen address:port
  -r or --remote <IP or Hostname:Port>    Remote address:port
  -s or --secret                          Shared secret
";

#[derive(Debug)]
struct AppArgs {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    secret: [u8; 32],
}

fn parse_socket_addr(s: &str) -> Result<SocketAddr, std::io::Error> {
    // without DNS
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // use DNS
    s.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "could not resolve address")
    })
}

async fn create_dual_stack_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
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
        .value_from_str("--remote")
        .or_else(|_| pargs.value_from_str("-r"))?;
    let secret: String = pargs
        .value_from_str("--secret")
        .or_else(|_| pargs.value_from_str("-s"))?;

    let secret32 = repeat_string_to_bytes(&secret, 32);
    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(&secret32);

    let args = AppArgs {
        local_addr: parse_socket_addr(&local_str).expect("Failed to parse listening address"),
        remote_addr: parse_socket_addr(&remote_str).expect("Failed to parse the remote address"),
        secret: secret_arr,
    };

    Ok(args)
}

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
    println!("  Obfuscating and forwarding wireguard to {}", args.remote_addr);

    let mut buf = [0u8; 1500];
    let mut client_registry: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
    loop {
        let (len, client_addr) = listener.recv_from(&mut buf).await?;
        let relay_socket = if let Some(s) = client_registry.get(&client_addr) {
            s.clone()
        } else {
            // create a dedicated socket to remote peer for the new client
            let s = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
            s.connect(args.remote_addr).await?;
            println!("Accept client {}", client_addr);

            client_registry.insert(client_addr, s.clone());

            // listen for return traffic from the server to THIS client
            let recv_socket = s.clone();
            let listen_socket = listener.clone();
            tokio::spawn(async move {
                let mut srv_buf = [0u8; 1500];
                loop {
                    let n = recv_socket.recv(&mut srv_buf).await.unwrap();
                    // unobfs and forward response back to the original client
                    let mut rnd_len: usize = 0;
                    match unobfs_udp_payload(&mut srv_buf, n, &args.secret, &mut rnd_len) {
                        ForwardState::NFDrop => (),
                        ForwardState::XTContinue => {
                            let _ = listen_socket
                                .send_to(&srv_buf[..n - rnd_len], client_addr)
                                .await;
                        }
                    }
                }
            });

            s
        };

        let mut rnd_len_out: usize = 0;
        match obfs_udp_payload(&mut buf, len, &args.secret, &mut rnd_len_out) {
            ForwardState::NFDrop => (),
            ForwardState::XTContinue => {
                relay_socket.send(&buf[..len + rnd_len_out]).await?;
            }
        }
    }
}
