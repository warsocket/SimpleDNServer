#!/usr/bin/env python3
import struct
import sys
VERSION_MAJOR = 1
VERSION_MINOR = 1
num_records = 1

chunk = bytearray(b"\x00"*1024)
chunk[0x000:0x000+8] = b"DNSTREAM"
chunk[0x008:0x008+16] = struct.pack(">QLL", 1, VERSION_MAJOR, VERSION_MINOR)
chunk[0x3F8:0x3F8+8] = struct.pack(">Q", num_records)

# print(len(chunk))
assert(len(chunk) == 1024)
sys.stdout.buffer.write(chunk)

#now emit 1 record

wire_domain = b"\x07example\x05local\x00"
data = b"\x7F\x02\x03\x04"
dns_type = b"\x00\x01"
reserved = b"\x00\x01"

chunk = bytearray(b"\x00"*1024)
chunk[0x000:0x000+8] = b"RECORD\x00\x00"
chunk[0x008:0x008+16] = struct.pack(">QLL", 1, VERSION_MAJOR, VERSION_MINOR)
chunk[0x0F8] = 0
chunk[0x0F9] = len(wire_domain)
chunk[0x0FA:0x0FA+2] = struct.pack(">H", len(data))
chunk[0x0FC:0x0FC+2] = dns_type
chunk[0x0FE:0x0FE+2] = reserved

chunk[0x100:0x100+len(wire_domain)] = wire_domain
chunk[0x200:0x200+len(data)] = data

assert(len(chunk) == 1024)
sys.stdout.buffer.write(chunk)