#!/usr/bin/env python3
import struct
import sys
import re
VERSION_MAJOR = 2
VERSION_MINOR = 1
num_records = 1

chunk = bytearray(b"\x00"*1024)
chunk[0x000:0x000+8] = b"DNSTREAM"
chunk[0x008:0x008+16] = struct.pack(">QLL", 1, VERSION_MAJOR, VERSION_MINOR)
chunk[0x3F8:0x3F8+8] = struct.pack(">Q", num_records)

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

	assert(len(chunk) == 1024)

	return chunk


record_data = {
	"A": lambda x: (1, struct.pack(">BBBB", *[int(s) for s in x.split(".")]) )
}

record_class = {
	"IN": 1
}

################################################################################
for line in sys.stdin:
	(domain_name, dns_ttl, dns_class, dns_type, dns_data) = re.split(" +|\t+|\n+", line.rstrip(), 4)


wire_type_value, wire_data = record_data[dns_type](dns_data)
chunk = record( domain_name, int(dns_ttl), record_class[dns_class], wire_type_value, wire_data )

sys.stdout.buffer.write(chunk)