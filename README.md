![Language](https://img.shields.io/badge/language-Rust-orange.svg)

`rs-wgobfs` is a cross-platform WireGuard obfuscator written in Rust. It is
fully compatible with [xt_wgobfs](https://github.com/infinet/xt_wgobfs).

- `rs-wgobfs`: Cross-platform CLI tool. Runs on Windows, Mac, BSD, and pfSense.
  iperf3 reaches 670 Mbits/sec in a Windows VM with 8th gen Intel CPU.

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
  -s or --secret                      Shared secret
  -m or --mode <obfs|unobfs>          Mode, either obfs or unobfs
```

To obfuscate WG to a remote peer, first update the WG configuration, replace the
ip/hostname and port of the remote peer with `listen_ip:listen_port` of
`rs-wgobfs`. Then run:

```
rs-wgobfs -l listen_ip:listen_port -f wg_server:port -s mysecretkey -m obfs
```

To accept obfucated WG traffic from clients on a WG server:

```
rs-wgobfs -l listen_ip:listen_port -f wg_server:port -s mysecretkey -m unobfs
```
