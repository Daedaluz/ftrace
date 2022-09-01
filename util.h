
void store(pid_t pid, struct ptrace_syscall_info* info);
struct ptrace_syscall_info* fetch(pid_t pid);
int file_inode(const char *file);
char *real_file(pid_t pid, int fd);
ssize_t *read_memory(pid_t pid, void *addr, void *raddr, size_t size);
