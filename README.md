# Timingless

A SOCKS5 proxy that sits between your applications and Tor, enforcing constant bandwidth to defeat traffic timing analysis. Real traffic is throttled and blended with cover traffic so that an observer (ISP, government) cannot distinguish active usage from idle periods.

![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)

---

# Quick start (copy - paste - enter)
```sh
apt update -y && apt install -y git clang make && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/timingless && cd timingless && v -prod timingless.v -o timingless && ln -sf $(pwd)/timingless $PREFIX/bin/timingless && timingless
```

---

## Problem

Even when using Tor, an ISP can observe metadata:

- When you come online and go offline.
- When you send a message (a small upload burst).
- When you download a file (a large download burst).
- Your daily usage pattern (sleep, work, breaks).

This metadata alone is enough to profile users without ever decrypting their traffic.

---

## Solution

Timingless maintains a constant-rate encrypted stream to Tor at all times. When you are not using the network, cover traffic fills the bandwidth. When you are active, cover traffic backs off and your real traffic takes its place. The total throughput stays flat.

```
Without Timingless:
  00:00 ░░░░░░░░░░░░░░░░░░░░░░░░  (sleeping, no traffic)
  08:00 ████░░██████░░░░████░░░░░  (wake up, check messages)
  12:00 ░░░░░░░░░░░░░░░░░░░░░░░░  (lunch, offline)
  18:00 ████████████████████░░░░░  (evening browsing)
  ISP conclusion: "User is active 08:00-09:00 and 18:00-22:00"

With Timingless:
  00:00 ████████████████████████
  08:00 ████████████████████████
  12:00 ████████████████████████
  18:00 ████████████████████████
  ISP conclusion: "Constant low-bandwidth stream. Cannot determine activity."
```

---

## How It Works

1. A token bucket regulates all outbound traffic to a fixed rate.
2. Multiple cover threads make HTTP requests to common websites through Tor, consuming tokens when the bucket has capacity.
3. Real traffic (your application) gets priority over cover traffic.
4. When real traffic increases, cover traffic decreases by the same amount. Total stays constant.
5. Tor circuits are rotated periodically to reduce correlation.

```
your app --> :8889 (timingless) --> :9050 (tor) --> internet
                |
                +-- cover thread 1 --> tor --> wikipedia
                +-- cover thread 2 --> tor --> bbc
                +-- cover thread N --> tor --> ...
```

---

## Requirements

- Tor service running on 127.0.0.1:9050
- Tor control port on 127.0.0.1:9051 (optional, for circuit rotation)
- V compiler

---

## Build

```
v -prod -o timingless timingless.v
```

---

## Usage

```
./timingless                  # 15 KB/s, 3 cover streams
./timingless -bw 20 -s 10     # 20 KB/s, 10 cover streams
```

Arguments:

- `-bw N` : Target constant bandwidth in KB/s (default: 15)
- `-s N`  : Number of concurrent cover threads (default: 3)

Configure your application to use SOCKS5 proxy at 127.0.0.1:8889.

---

## Tuning

The two numbers that matter are bandwidth and noise ratio.

**Bandwidth (-bw):** Higher values give better usability but look less like a standby device. Lower values are more stealthy but slower. Recommended range is 10-30 KB/s.

**Streams (-s):** If your noise ratio is below 50%, increase the stream count. Tor connections are slow to establish, so more threads ensure the bucket stays full. Start with 10 and adjust.

**Noise target:** Above 60% means most of what the ISP sees is cover traffic. Your real usage is buried in noise. Below 40% means your real traffic dominates and timing patterns may leak through.

---

## Example Output

```
timingless
  listen:  127.0.0.1:8889
  tor:     127.0.0.1:9050
  target:  20 KB/s constant
  streams: 10

ready
  [stat] rate=4.4K/s noise=68% conn=7 reqs=7 cover=84
  [stat] rate=3.9K/s noise=73% conn=7 reqs=7 cover=111
  [stat] rate=4.7K/s noise=59% conn=10 reqs=10 cover=221
  [stat] rate=4.6K/s noise=69% conn=10 reqs=10 cover=422
```

In this session, noise stays between 59-73%. The rate hovers around 4-5 KB/s. An ISP sees a flat, low-bandwidth Tor stream indistinguishable from a background service.

---

## Limitations

- Tor itself is the bottleneck. If Tor is slow, the target bandwidth may not be reached.
- Media-heavy applications (video, large file downloads) will be very slow at low bandwidth targets.
- This tool addresses timing and volume analysis. It does not protect against other attacks (compromised exit nodes, application-level leaks, etc.).
- Cover traffic consumes real bandwidth and Tor network resources.
