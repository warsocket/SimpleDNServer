#!/usr/bin/env python3
import struct
import sys
import re
VERSION_MAJOR = 2
VERSION_MINOR = 1


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

	# print(chunk)
	return chunk

record_type = {
	"A": 1,
	"NS": 2,
	"AAAA": 28,
	"SOA": 6,
}

def ipv4wire(string):
	try:
		return struct.pack(">BBBB", *[int(s) for s in string.split(".")])
	except struct.error:
		raise ValueError


def ipv6wire(string):
	dOctets = string.split(":")
	buffer = bytearray()



	if string.startswith("::"): 
		dOctets = dOctets[1:]
	else:
		if string[0] == ":": raise ValueError

	if string.endswith("::"): 
		dOctets.pop()
	else:
		if string[-1] == ":": raise ValueError

	if len(string.split("::")) > 2: raise ValueError

	buffers = [bytearray(), bytearray()]
	buffer = buffers[0]

	for d in dOctets:
		if d == "":
			buffer = buffers[-1]
		elif "." in d:
			buffer.extend(ipv4wire(d))
			pass
		else:
			try:
				buffer.extend(struct.pack(">H",int(d,0x10)))
			except struct.error:
				raise ValueError 

	#craft wire fmt
	buffer = buffers[0]

	#check how much we need to fill due to ::
	cSize = len(buffers[0]) + len(buffers[1])
	if cSize >16: raise ValueError
	buffer.extend((b"\x00")*(16-cSize))
	buffer.extend(buffers[-1])

	if len(buffer) != 16: raise ValueError
	return bytes(buffer)


def soawire(string):
	split = re.split(" +|\t+|\n+", string, 6)
	
	try:
		(nameserver, email, serial, refresh, retry, expire, ttl) = re.split(" +|\t+|\n+", string, 6)
	except ValueError:
		raise ValueError

	buffer = bytearray()
	buffer.extend( domain2wire(nameserver) ),
	buffer.extend( domain2wire(email) ),
	buffer.extend( struct.pack(">LLLLL", *map(lambda x:int(x), [serial, refresh, retry, expire, ttl])) )

	return bytes(buffer)
	


record_data = {
	"A": ipv4wire,
	"NS": lambda x: domain2wire(x),
	"AAAA": ipv6wire,
	"SOA": soawire,
}

record_class = {
	"IN": 1,
}

# wipv6 = ipv6wire("::ffff:abcd:1.1.1.1")
# print(wipv6.hex())
# print(len(wipv6))

# exit()



################################################################################
records = []
for line in sys.stdin:

	line = line.rstrip().split("#",1)[0] #remove trailing  newline, remove comments
	split = re.split(" +|\t+|\n+", line, 4) # split into parameters
	if split == [""]: continue # ignore empty lines

	try:
		(domain_name, dns_ttl, dns_class, dns_type, dns_data) = split
	except ValueError: 
		print(f"Warning: Ignoring malformed config statement: '{line}' ", file=sys.stderr)

	records.append(
		record( domain_name, int(dns_ttl), record_class[dns_class], record_type[dns_type], record_data[dns_type](dns_data) )
	)


chunk = bytearray(b"\x00"*1024)
chunk[0x000:0x000+8] = b"DNSTREAM"
chunk[0x008:0x008+16] = struct.pack(">QLL", 1, VERSION_MAJOR, VERSION_MINOR)
chunk[0x3F8:0x3F8+8] = struct.pack(">Q", len(records))
assert(len(chunk) == 1024)
sys.stdout.buffer.write(chunk)

for record in records:
	sys.stdout.buffer.write(record)