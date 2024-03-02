#!/usr/bin/env bash
cargo build --release
cat dns.conf | ./rundns.py | sudo ./target/release/dns

