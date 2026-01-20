![Language](https://img.shields.io/badge/language-Rust-orange.svg)

`rs-wgobfs` is a cross-platform WireGuard obfuscator written in Rust. It is
fully compatible with [xt_wgobfs](https://github.com/infinet/xt_wgobfs).

- `rs-wgobfs`: Cross-platform CLI tool. Runs on Windows, OpenBSD, FreeBSD, and
   pfSense. It should work on macOS (untested).
   Iperf3 reaches 820 Mbits/sec in a Windows VM with 8th gen Intel CPU.

- `xt_wgobfs`: High-performance Linux kernel module. Works on Linux, including
  embedded devices with very limited resources (e.g. routers).


## Building

Run `cargo build --release` from inside the `rs-wgobfs` directory.


## Usage

```
rs-wgobfs -h

USAGE:
  rs-wgobfs [OPTIONS]

OPTIONS:
  -h, --help                          Print help information
  -l or --listen <IP:Port>            Listen address:port
  -f or --forward <IP|Hostname:Port>  Peer's address:port
  -6                                  (Optional) Prefer IPv6 when connecting
                                      to the forward Peer

  -k or --key                         Shared secret (will be repeated or
                                      truncated to 32 characters)

  -m or --mode <obfs|unobfs>          Mode, either obfs or unobfs
```

To obfuscate WG to a remote peer, first update the WG configuration, replace the
ip/hostname and port of the remote peer with `listen_ip:listen_port` of
`rs-wgobfs`. Then run:

```
rs-wgobfs -l listen_ip:listen_port -f wg_server:port -k mysecretkey -m obfs
```

To accept obfucated WG traffic from clients on a WG server:

```
rs-wgobfs -l listen_ip:listen_port -f wg_server:port -k mysecretkey -m unobfs
```
