#!/usr/bin/env python3
import socket
import struct


NOERROR = 0
FORMERR = 1
SERVFAIL = 2
NXDOMAIN = 3
NOTIMP = 4
REFUSED = 5
YXDOMAIN = 6
XRRSET = 7
NOTAUTH = 8
NOTZONE = 9

def parse_header(data):
	(tid, flags0, flags1, q, a, auth_rr, add_rr) = struct.unpack(">HBBHHHH", data)
	return {
		"tid": tid,
		"flags":{
			"response": bool(flags0 & 0b10000000),
			"opcode": (flags0 & 0b01111000) >> 3,
			"authorative": bool(flags0 & 0b00000100),
			"truncated": bool(flags0 & 0b00000010),
			"recrsion_req": bool(flags0 & 0b00000001),

			"recrsion_avail": bool(flags1 & 0b10000000),
			"Z": bool(flags1 & 0b01000000),
			"answer_authenticated": bool(flags1 & 0b00100000),
			"non_authenticated_data_accepted": bool(flags1 & 0b00010000),
			"reply": flags1 & 0b00001111
			
		},
		"q": q,
		"a": a,
		"auth_rr": auth_rr,
		"add_rr": add_rr,
	}


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def perform(dns_type, wire_name):
	sock.sendto(b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + wire_name + dns_type + b"\x00\x01", ("127.53.53.53",53))
	(data,_) = sock.recvfrom(0xFFFF)
	return parse_header(data[:12])


# check well known request
header = perform(b"\x00\x01", b"\x02ns\06domain\x05local\x00")

assert( header["flags"]["response"] )
assert( header["flags"]["opcode"] == 0 )

assert( header["flags"]["authorative"] )
assert( header["flags"]["reply"] == NOERROR )

#######################################

# check well known request, extending range beyongf udp packet + using disallowed bits
header = perform(b"\x00\x01", b"\x02ns\06domain\x05local\x00")
assert( header["flags"]["reply"] == NOERROR )

for b in range(1,0x100):
	header = perform(b"\x00\x01", b"\x02ns\06domain\x05local" + bytes([b]))
	assert( header["flags"]["reply"] == FORMERR )

#######################################

# check if unknown domains leads to refused and know domains + sub parts to NXdomain and or an answer
header = perform(b"\x00\x01", b"\07example\x05local\x00")
assert( header["flags"]["reply"] == REFUSED )

header = perform(b"\x00\x01", b"\x06domain\x05local\x00")
assert( header["flags"]["reply"] == NXDOMAIN )

header = perform(b"\x00\x01", b"\x03www\x06domain\x05local\x00")
assert( header["flags"]["reply"] == NOERROR )
#######################################