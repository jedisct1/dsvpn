# ![DSVPN](https://raw.github.com/jedisct1/dsvpn/master/logo.png)

DSVPN is a Dead Simple VPN, designed to address the most common use case for using a VPN:

```text
[client device] ---- (untrusted/restricted network) ---- [vpn server] ---- [the Internet]
```

Features:

* Runs on TCP. Works pretty much everywhere, including on public WiFi where only TCP/443 is open or reliable.
* Secure. Doesn't perform any heap memory allocations. Uses modern cryptography.
* Tiny (~ 17 Kb), with an equally small and readable code base.
* No external dependencies
* Works out of the box. No lousy documentation to read. No configuration file. No post-configuration. Run a single-line command on the server, a similar one on the client and you're done. No firewall and routing rules to manually mess with.
* Works with Linux (client, server), MacOS (client), FreeBSD (client) and OpenBSD (client). Adding support for other operating systems is trivial.
* Blocks IPv6 on the client to prevent IPv6 leaks.

Next:

* Optimized ARM (NEON) implementation

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

## Example usage on the server

```sh
sudo ./dsvpn server vpn.key auto 1959
```

Here, I use port `1959`. Everything else is set to the default values. If you want to use the default port (`443`), it doesn't even have to be specified, so the parameters can just be `server vpn.key`

## Example usage on the client

```sh
sudo ./dsvpn client vpn.key 34.216.127.34 1959
```

This is a MacOS client, connecting to the VPN server `34.216.127.34` on port `1959`. The port number is optional as well.

On MacOS, the VPN server can be specified as a host name. Linux currently requires an IP address.

## That's it

You are connected.

## Advanced configuration

```text
dsvpn   "server"
        <key file>
        <vpn server ip>|"auto"
        <vpn server port>|"auto"
        <tun interface>|"auto"
        <local tun ip>|"auto"
        <remote tun ip>"auto"
        <external ip>|"auto"

dsvpn   "client"
        <key file>
        <vpn server ip>
        <vpn server port>|"auto"
        <tun interface>|"auto"
        <local tun ip>|"auto"
        <remote tun ip>|"auto"
        <gateway ip>|"auto"
```

* `server`|`client`: use `server` on the server, and `client` on clients.
* `<key file>`: path to the file with the secret key (e.g. `vpn.key`).
* `<vpn server ip>`: on the client, it should be the IP address or the hostname of the server. On the server, it doesn't matter, so you can just use `auto`.
* `<vpn server port>`: the TCP port to listen to/connect to for the VPN. Use 443 or anything else. `auto` will use `443`.
* `<tun interface>`: this is the name of the VPN interface. On Linux, you can set it to anything. Or MacOS, it has to follow a more boring pattern. If you feel lazy, just use `auto` here.
* `<local tun ip>`: local IP address of the tunnel. Use any private IP address that you don't use here.
* `<remote tun ip>`: remote IP address of the tunnel. See above. The local and remote tunnel IPs must the same on the client and on the server, just reversed. For some reason, I tend to pick `192.168.192.254` for the server, and `192.168.192.1` for the client. These values will be used if you put `auto` for the local and remote tunnel IPs.
* `<external ip>` (server only): the external IP address of the server. Can be left to `"auto"`.
* `<gateway ip>` (client only): the internal router IP address. Once again, the first line printed by `netstat -rn` will tell you (`gateway`).

If all the remaining parameters of a command would be `auto`, they don't have to be specified.

## Why

I needed a VPN that works in an environment where only TCP/80 and TCP/443 are open.

WireGuard doesn't work over TCP.

GloryTun is excellent, but requires post-configuration and the maintained branch uses UDP.

OpenVPN is horribly difficult to set up.

Sshuttle is very nice and I've been using it a lot in the past, but it's not a VPN. It doesn't tunnel non-TCP traffic. It also requires a full Python install, which I'd rather avoid on my router.

Everything else I looked at was either too difficult to use, slow, bloated, didn't work on MacOS, didn't work on small devices, was complicated to cross-compile due to dependencies, wasn't maintained, or didn't feel secure.

TCP-over-TCP is not as bad as some documents describe. It works surprisingly well in practice, especially with modern congestion control algorithms (bbr). For traditional algorithms that rely on packet loss, DSVPN has the ability to emulate congestion in the wrapped layer, by setting the `BUFFERBLOAT_CONTROL` macro to `1`.

## Cryptography

The cryptographic primitives used in DSVPN are available as a standalone project: [Charm](https://github.com/jedisct1/charm).

## Guarantees, support, feature additions

None.

This is a weekend project, and this is what I use, because it solves a problem I had. Extending it to solve different problems is not planned, but feel free to fork it and tailor it to your needs!
