#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/uio.h>


int file_inode(const char *file) {
    struct stat file_stat;
    int fd = 0;
    fd = open(file, O_RDONLY);
    if (fd == -1) {
        return -1;
    }
    if (fstat(fd, &file_stat) == -1) {
        return -1;
    }
    close(fd);
    return file_stat.st_ino;
}


char *real_file(pid_t pid, int fd) {
    char *path = calloc(FILENAME_MAX, 1);
    char *realPath = malloc(FILENAME_MAX);
    sprintf(path, "/proc/%d/fd/%d", pid, fd);
    size_t s = readlink(path, realPath, FILENAME_MAX - 1);
    realPath[s] = 0;
    free(path);
    return realPath;
}

ssize_t read_memory(pid_t pid, void *addr, void *raddr, size_t size) {
    struct iovec local;
    struct iovec remote;
    local.iov_base = addr;
    local.iov_len = size;
    remote.iov_base = raddr;
    remote.iov_len = size;
    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

struct node {
    struct node *next;
    pid_t pid;
    struct ptrace_syscall_info *data;
};


static struct node root;

void store(pid_t pid, struct ptrace_syscall_info* info) {
    struct node* cur;
    for(cur = &root; cur->pid != pid && cur->next != NULL; cur = cur->next);
    if(cur->pid == pid) {
        free(cur->data);
        cur->data = info;
        return;
    }
    struct node* new = calloc(1, sizeof(struct node));
    new->data = info;
    new->pid = pid;
    cur->next = new;
}

struct ptrace_syscall_info* fetch(pid_t pid) {
    struct node* cur;
    for(cur = &root; cur->pid != pid && cur->next != NULL; cur = cur->next);
    if(cur->pid == pid) {
        return cur->data;
    }
    return NULL;
}