#!/usr/bin/env python3
import struct
import sys
VERSION_MAJOR = 2
VERSION_MINOR = 1
num_records = 1

chunk = bytearray(b"\x00"*1024)
chunk[0x000:0x000+8] = b"DNSTREAM"
chunk[0x008:0x008+16] = struct.pack(">QLL", 1, VERSION_MAJOR, VERSION_MINOR)
chunk[0x3F8:0x3F8+8] = struct.pack(">Q", num_records)

# print(len(chunk))
assert(len(chunk) == 1024)
sys.stdout.buffer.write(chunk)


def domain2wire(domain):
	b = bytearray()

	for sub in domain.split("."):
		if not sub : continue
		b.append(len(sub))
		b += sub.encode("ASCII")

	b.append(0)
	return bytes(b)


def record(domain_name, dns_ttl, dns_class, dns_type, dns_data):
	chunk = bytearray(b"\x00"*1024)
	wire_domain = domain2wire(domain_name)

	chunk[0x0F4:0x100] = struct.pack(">LHHBBH", dns_ttl, dns_class, dns_type, 0, len(wire_domain), len(dns_data))
	chunk[0x100:0x100+len(wire_domain)] = wire_domain
	chunk[0x200:0x200+len(dns_data)] = dns_data

	return chunk


chunk = record("example.local", 300, 1, 1, b"\x7F\x01\x02\x03")
assert(len(chunk) == 1024)

sys.stdout.buffer.write(chunk)