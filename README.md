# Rust Implementation of WireGuard Obfuscation

`rs-wgobfs` is a companion of [xt_wgobfs](https://github.com/infinet/xt_wgobfs).
While `xt_wgobfs` is a Linux kernel module therefor only works on Linux,
`rs-wgobfs` shall work on Windows, BSDs and Mac.


## Building

Run `cargo build --release` from inside the `rs-wgobfs` directory.


## Usage

Run:

```
    rs-wgobfs -h

    USAGE:
      rs-wgobfs [OPTIONS]

    OPTIONS:
      -h, --help                              Prints help information
      -l or --listen <IP:Port>                Listen address:port
      -r or --remote <IP or Hostname:Port>    Remote address:port
      -s or --secret                          Shared secret

    rs-wgobfs -l listen_ip:listen_port -r remote_wg:remote_port -s mysecretkey
```

In wireguard configure, replace the ip/hostname and port of remote peer with
`listen_ip:listen_port` of `rs-wgobfs`.


## Performance

Test with iperf3, `rs-wgobfs` reaches 500Mbits/sec on a testing machine. The
Linux kernel module `xt_wgobfs` is over 900Mbits/sec on the same machine.
