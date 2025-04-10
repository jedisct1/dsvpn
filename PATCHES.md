# DSVPN Patches for XRay Integration

This repository contains patches for DSVPN that enhance its functionality for use with XRay VLESS Reality for IoT devices.

## Available Patches

1. **nocrypto-patch.diff**: Adds a "nocrypto" option to DSVPN that disables encryption, useful when XRay is already providing encryption.

2. **noroutes-patch.diff**: Adds a "noroutes" option to DSVPN that prevents automatic route configuration for manual control.

3. **combined-patch.diff**: Adds both "nocrypto" and "noroutes" options to DSVPN:
   - `nocrypto`: Disables encryption to avoid double encryption when using XRay
   - `noroutes`: Prevents automatic route configuration for manual control

4. **zig-update.diff**: Basic update to the build.zig file for compatibility with newer Zig versions.

5. **zig-update-modern.diff**: Comprehensive update for the build.zig file for latest Zig versions (0.11.0+) with additional features.

## How to Apply

Apply these patches to the DSVPN source code:

```bash
# Clone DSVPN repository
git clone https://github.com/jedisct1/dsvpn.git
cd dsvpn

# Apply one of the following patches based on your needs:

# Option 1: Just disable encryption (nocrypto)
patch -p0 < ../nocrypto-patch.diff

# Option 2: Just disable automatic routes (noroutes)
patch -p0 < ../noroutes-patch.diff

# Option 3: Apply both features (combined - recommended)
patch -p0 < ../combined-patch.diff

# For Zig users, apply one of the Zig patches:
# For basic Zig compatibility:
patch -p0 < ../zig-update.diff

# OR for modern Zig (0.11.0+) with additional features:
patch -p0 < ../zig-update-modern.diff

# Build with Make
make

# OR build with Zig
zig build

# With modern Zig patch, you can also run directly:
zig build run -- server keyfile 0.0.0.0 10000 tun0 10.10.0.1 10.10.0.2 auto nocrypto
```

## Using the Patched DSVPN

### With No-Crypto Option Only

```bash
# Server
sudo ./dsvpn server keyfile 0.0.0.0 10000 tun0 10.10.0.1 10.10.0.2 auto nocrypto

# Client
sudo ./dsvpn client keyfile SERVER_IP 10000 tun0 10.10.0.2 10.10.0.1 auto nocrypto
```

### With Both No-Crypto and No-Routes Options

```bash
# Server
sudo ./dsvpn server keyfile 0.0.0.0 10000 tun0 10.10.0.1 10.10.0.2 auto nocrypto noroutes

# Client
sudo ./dsvpn client keyfile SERVER_IP 10000 tun0 10.10.0.2 10.10.0.1 auto nocrypto noroutes
```

When using the `noroutes` option, you'll need to manually configure routes:

```bash
# On server
ip link set dev tun0 up
ip addr add 10.10.0.1 peer 10.10.0.2 dev tun0

# On client
ip link set dev tun0 up
ip route add 192.168.1.0/24 dev tun0
```

## Modern Zig Build Features

The **zig-update-modern.diff** patch provides several improvements:

1. **Full compatibility** with Zig 0.11.0 and newer
2. **Optimized binary size** with `.ReleaseSmall` optimization mode
3. **Run command support** - build and run in one step with `zig build run`
4. **Argument passing** - pass arguments with `zig build run -- arg1 arg2`
5. **Modern API usage** with `root_module.addCMacro` instead of `defineCMacro`

To use these features:
```bash
# Apply the modern Zig patch
patch -p0 < ../zig-update-modern.diff

# Build and run in one step (example for server)
zig build run -- server keyfile 0.0.0.0 10000 tun0 10.10.0.1 10.10.0.2 auto nocrypto
```

## Undocumented Features and Performance Tuning

Besides the "nocrypto" and "noroutes" options, DSVPN has several other undocumented features and optimization options:

### Compile-Time Optimization Options

These options can be set during compilation using CFLAGS:

```bash
make CFLAGS="-D<OPTION>=<VALUE>"
```

#### 1. MTU Configuration

```bash
make CFLAGS="-DDEFAULT_MTU=<size>"
```

The default MTU is set to 9000 (jumbo frames) on most platforms, but you can change it to match your network needs. A higher MTU can improve performance but may cause fragmentation issues.

#### 2. BUFFERBLOAT_CONTROL (Default: Enabled)

```bash
make CFLAGS="-DBUFFERBLOAT_CONTROL=0"  # To disable
```

This feature helps prevent network congestion by using TCP_NOTSENT_LOWAT to limit how much data is queued. It's particularly useful for real-time applications but can slightly reduce maximum throughput.

#### 3. NOTSENT_LOWAT Buffer Size

```bash
make CFLAGS="-DNOTSENT_LOWAT=<size>"
```

Default is 128KB. Increasing this value allows more data to be queued before throttling, which can improve throughput at the cost of potential latency spikes.

#### 4. XOODOO_ROUNDS (Encryption Performance)

```bash
make CFLAGS="-DXOODOO_ROUNDS=<rounds>"
```

Default is 12 rounds. You can reduce this for better performance at the cost of security (not relevant when using the "nocrypto" option).

#### 5. TIMEOUT Values

```bash
make CFLAGS="-DTIMEOUT=<milliseconds>"
make CFLAGS="-DACCEPT_TIMEOUT=<milliseconds>"
```

The default timeout for connections is 60 seconds (60000ms). You can adjust these values for more aggressive reconnection behavior.

#### 6. RECONNECT_ATTEMPTS

```bash
make CFLAGS="-DRECONNECT_ATTEMPTS=<number>"
```

Default is 100 attempts. You can increase this for more persistent reconnection behavior.

### Runtime Features

#### 1. Custom Interface Names

```bash
sudo ./dsvpn client keyfile SERVER_IP 10000 custom-tun0 10.10.0.2 10.10.0.1
```

You can specify a custom interface name as the 5th parameter.

#### 2. BBR Congestion Control Algorithm

DSVPN automatically enables BBR congestion control on Linux, which can significantly improve performance on high-latency connections. This is set by the `OUTER_CONGESTION_CONTROL_ALG` define.

To use a different algorithm:

```bash
make CFLAGS="-DOUTER_CONGESTION_CONTROL_ALG=\\\"cubic\\\""
```

#### 3. TS_TOLERANCE for Clock Differences

When not using nocrypto mode, DSVPN has a timestamp tolerance of 7200 seconds (2 hours) for clock differences between server and client. You can adjust this if you have larger clock skew:

```bash
make CFLAGS="-DTS_TOLERANCE=<seconds>"
```

### Optimization Profiles for XRay Integration

#### 1. Low Latency Mode

Combining various options can create a low-latency profile ideal for IoT devices:

```bash
make CFLAGS="-DBUFFERBLOAT_CONTROL=1 -DNOTSENT_LOWAT=16384 -DTIMEOUT=30000"
```

This creates a configuration optimized for responsiveness rather than maximum throughput.

#### 2. High Throughput Mode

For scenarios where bandwidth is more important than latency:

```bash
make CFLAGS="-DBUFFERBLOAT_CONTROL=0 -DDEFAULT_MTU=9000"
```

This prioritizes throughput over latency.

#### 3. Fast Reconnection Profile

For unstable connections:

```bash
make CFLAGS="-DRECONNECT_ATTEMPTS=500 -DTIMEOUT=10000 -DACCEPT_TIMEOUT=5000"
```

This creates a more aggressive reconnection behavior for unreliable networks.

## Integration with XRay VLESS Reality

1. Set up DSVPN with the `nocrypto noroutes` options
2. Configure XRay with VLESS Reality for secure transport
3. Configure routes manually to control traffic flow

All of these optimization options can be combined with our "nocrypto" and "noroutes" features to create a highly optimized solution for your specific XRay IoT setup.
