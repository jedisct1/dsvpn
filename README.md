# ![DSVPN](https://raw.github.com/jedisct1/dsvpn/master/logo.png)

DSVPN is a Dead Simple VPN, designed to address the most common use case for using a VPN:

```text
[client device] ---- (untrusted/restricted network) ---- [vpn server] ---- [the Internet]
```

Features:

* Runs on TCP. Works pretty much everywhere, including on public WiFi where only TCP/443 is open or reliable.
* Secure
* Tiny (~ 17 Kb), with an equally small and readable code base.
* No external dependencies
* Works out of the box. No lousy documentation to read. No configuration file. No post-configuration. Run a single-line command on the server, a similar one on the client and you're done. No firewall and routing rules to manually mess up with.
* Works with Linux (client, server), MacOS (client) and OpenBSD (client). Adding support for other operating systems is trivial.
* Blocks IPv6 on the client to prevent IPv6 leaks.

Next:

* Optimized ARM (NEON) implementation
* Clean shutdown

Maybe:

* The ability to run custom commands after the link is up
* Non-blocking key exchange, support for multiple clients

Non-features:

* Anything else. Including supporting operating systems I don't use.

## Installation

```sh
cd src && make
```

## Secret key

DSVPN uses a shared secret. Create it with the following command:

```sh
dd if=/dev/urandom of=vpn.key count=1 bs=32
```

And copy it on the server and the client.

## Usage

```text
dsvpn "server"|"client" <key file> <interface>|"auto" <local tun ip> <remote tun ip>
      <external host>|"auto" <external port> <external interface>
      <external gateway ip>|"auto"
```

* `server`|`client`: either `server` or `client`.
* `interface`: this is the name of the VPN interface. On Linux, you can set it to anything. Or MacOS, it has to follow a more boring pattern. If you feel lazy, just use `auto` here.
* `<key file>`: path to the file with the secret key (e.g. `vpn.key`).
* `<local tun ip>`: local IP address of the tunnel. Use any private IP address that you don't use here. For some reason, I tend to pick `192.168.192.254` for the server, and `192.168.192.1` for the client.
* `<remote tun ip>`: remote IP address of the tunnel. See above. These parameters must the same on the client and on the server, just reversed.
* `<external host>`: on the client, it should be the IP address or the hostname of the server. On the server, it doesn't matter, so you can just use `auto`.
* `<external port>`: the TCP port to listen to/connect to for the VPN. Use 443 or anything else.
* `<external interface>`: the name of the external interface, that sends packets to the Internet. The first line of the `netstat -rn` output will tell you (`destination: default` or `destination: 0.0.0.0`).
* `<external gateway ip>`: the internal router IP address. Required on the client, can be left to `auto` on the server. Once again, the first line printed by `netstat -rn` will tell you (`gateway`).

## Example usage on the server

```sh
sudo ./dsvpn server vpn.key auto 192.168.192.254 192.168.192.1 auto 1959 eno1 auto
```

Here, I use port `1959`. This is a Linux box and the network interface is `eno1`.

## Example usage on the client

```sh
sudo ./dsvpn client vpn.key auto 192.168.192.1 192.168.192.254 34.216.127.34 1959 en0 192.168.1.1
```

This is a MacOS client, connecting to the VPN server `34.216.127.34` on port `1959`. Its WiFi interface name is `en0` and the local router address is `192.168.1.1`.

On MacOS, the VPN server can be specified as a host name. Linux currently requires an IP address.

## That's it

You are connected.

## Why

I needed a VPN that works in an environment where only TCP/80 and TCP/443 are open.

WireGuard doesn't work over TCP.

GloryTun is excellent, but requires post-configuration and the maintained branch uses UDP.

OpenVPN is horribly difficult to set up.

Sshuttle is very nice and I've been using it a lot in the past, but it's not a VPN. It doesn't tunnel non-TCP traffic. It also requires a full Python install, which I'd rather avoid on my router.

Everything else I looked at was either too difficult to use, slow, bloated, didn't work on MacOS, didn't work on small devices, was complicated to cross-compile due to dependencies, wasn't maintained, or didn't feel secure.

## Cryptography

The cryptographic primitives used in DSVPN are available as a standalone project: [Charm](https://github.com/jedisct1/charm).

## Guarantees, support, feature additions

None.

This is a weekend project, and this is what I use, because it solves a problem I had. Extending it to solve different problems is not planned, but feel free to fork it and tailor it to your needs!
