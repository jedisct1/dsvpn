# DSVPN with No-Crypto and No-Routes Options for XRay IoT Bridge

This is a modified version of DSVPN that adds optional "nocrypto" and "noroutes" modes, making it ideal for use with XRay VLESS Reality for IoT devices. This patch allows you to:

1. Disable encryption when XRay is already providing encryption
2. Manually control routing without DSVPN automatically adding routes
3. Create TUN interfaces for proper network addressing

## Features

- **No-Crypto Mode**: Bypass DSVPN's encryption layer to avoid double encryption
- **No-Routes Mode**: Prevent automatic route configuration for manual control
- **Compatible**: Both options can be used together or separately
- **Error Detection**: Automatically detects mismatched configurations

## Building

1. Apply the included patch to the DSVPN source code:

```bash
# Clone DSVPN repository
git clone https://github.com/jedisct1/dsvpn.git
cd dsvpn

# Apply the patch
patch -p0 < ../combined-patch.diff

# Build
make
```

## Usage

The modified DSVPN works with optional parameters:

### Server Side

```bash
# With both options
sudo ./dsvpn server keyfile 0.0.0.0 10000 tun0 10.10.0.1 10.10.0.2 auto nocrypto noroutes

# Only disable encryption
sudo ./dsvpn server keyfile 0.0.0.0 10000 tun0 10.10.0.1 10.10.0.2 auto nocrypto

# Only disable routes
sudo ./dsvpn server keyfile 0.0.0.0 10000 tun0 10.10.0.1 10.10.0.2 auto noroutes
```

### Client Side

```bash
# With both options
sudo ./dsvpn client keyfile SERVER_IP 10000 tun0 10.10.0.2 10.10.0.1 auto nocrypto noroutes

# Only disable encryption
sudo ./dsvpn client keyfile SERVER_IP 10000 tun0 10.10.0.2 10.10.0.1 auto nocrypto

# Only disable routes
sudo ./dsvpn client keyfile SERVER_IP 10000 tun0 10.10.0.2 10.10.0.1 auto noroutes
```

## Integration with XRay

### System B (Landing Server)

1. Set up DSVPN server:
   ```bash
   sudo ./dsvpn server keyfile 0.0.0.0 10000 tun0 10.10.0.1 10.10.0.2 auto nocrypto noroutes
   ```

2. Configure XRay server with VLESS Reality

3. Add manual routes:
   ```bash
   # Only needed when using 'noroutes' option
   ip link set dev tun0 up
   ip addr add 10.10.0.1 peer 10.10.0.2 dev tun0
   ```

### System A (IoT Device)

1. Set up DSVPN client:
   ```bash
   sudo ./dsvpn client keyfile SERVER_IP 10000 tun0 10.10.0.2 10.10.0.1 auto nocrypto noroutes
   ```

2. Configure XRay client with VLESS Reality

3. Add manual routes:
   ```bash
   # Only needed when using 'noroutes' option
   ip link set dev tun0 up
   ip route add 192.168.1.0/24 dev tun0
   ```

## Performance Benefits

Using the "nocrypto" option provides several benefits:

1. **Lower CPU Usage**: Eliminates encryption/decryption operations
2. **Reduced Latency**: Fewer processing steps for each packet
3. **Better Throughput**: Especially noticeable on CPU-constrained IoT devices

## Manual Routing Benefits

Using the "noroutes" option allows you to:

1. **Custom Routing Tables**: Create specific routes only for the services you need
2. **Selective Forwarding**: Direct only specific traffic through XRay
3. **Advanced Network Configurations**: Integrate with complex setups

## Troubleshooting

### Crypto Mode Mismatch

If you see this error:
```
Crypto mode mismatch: client is ENABLED but server is DISABLED
Use "nocrypto" parameter to match the server's configuration
```

Ensure both client and server are using the same crypto mode.

### Interface Not Working

If the TUN interface exists but doesn't pass traffic:

```bash
# Check interface status
ip addr show tun0

# When using 'noroutes', ensure manual routes are set
ip route show

# For debugging, try pinging directly
ping 10.10.0.1  # From client
ping 10.10.0.2  # From server
```

### XRay Integration Issues

If XRay and DSVPN aren't working together properly:

1. Ensure XRay is configured to use the correct TUN interface IP addresses
2. Check that firewall rules allow traffic between interfaces
3. Verify that XRay services can bind to the TUN interface

## Comparison with Alternatives

| Feature | Modified DSVPN | Original DSVPN | socat TUN | WireGuard |
|---------|---------------|---------------|-----------|-----------|
| TUN Interface | ✅ | ✅ | ✅ | ✅ |
| No Encryption Option | ✅ | ❌ | ✅ | ❌ |
| Manual Routing Option | ✅ | ❌ | ✅ | ❌ |
| Auto-reconnect | ✅ | ✅ | ❌ | ✅ |
| Low CPU Usage | ✅ (with nocrypto) | ❌ | ✅ | ❌ |
| Firewall Integration | ✅ | ✅ | ❌ | ✅ |
