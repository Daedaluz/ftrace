#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/ptrace.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/syscall.h>
#include "util.h"

static int target_inode = 0;
static int target_fd = -1;
static pid_t main_pid;
static char cwd[FILENAME_MAX];

void sig_handler(int signum) {
    if (signum == SIGINT) {
        _exit(0);
    }
}

void printbin(size_t size, char* data) {
    size_t cur = 0;
    for (cur = 0; cur < size; cur++) {
        printf("%.2X", *(data+cur) & 0xFF);
    }
    printf("\n");
}

void handle_syscall(pid_t pid, struct ptrace_syscall_info *entry, struct ptrace_syscall_info *exit) {
    switch (entry->entry.nr) {
        case SYS_open:
        case SYS_openat2:
        case SYS_openat: {
            if(exit->exit.rval >= 0) {
                char* file_name = real_file(main_pid, exit->exit.rval);
                int inode = file_inode(file_name);
                if(inode == target_inode) {
                    target_fd = exit->exit.rval;
                }
                free(file_name);
            }
        }
        case SYS_read:
            if (entry->entry.args[0] == target_fd) {
                size_t nread = exit->exit.rval;
                if(nread > 0) {
                    char* data = calloc(1, nread);
                    read_memory(pid, data, (void*)entry->entry.args[1], nread);
                    printf("Read:  ");
                    printbin(nread, data);
                }
            }
            break;
        case SYS_write:
            if (entry->entry.args[0] == target_fd) {
                size_t nwrite = exit->exit.rval;
                if(nwrite > 0) {
                    char* data = calloc(1, nwrite);
                    read_memory(pid, data, (void*)entry->entry.args[1], nwrite);
                    printf("Write: ");
                    printbin(nwrite, data);
                }
            }
            break;
        case SYS_close:
            if (entry->entry.args[0] == target_fd) {
                printf("Close!\n");
                target_fd = -1;
            }
            break;
    }
}


int main(int argc, char **argv) {
    if(argc < 3) {
        printf("ftrace <file> <program> [program args]\n");
        return 1;
    }

    target_inode = file_inode(argv[1]);
    getcwd(cwd, FILENAME_MAX);
    if (target_inode == -1) {
        printf("Error getting target_inode number: %s\n", strerror(errno));
        return -1;
    }
    main_pid = fork();
    pid_t pid = main_pid;

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    signal(SIGINT, sig_handler);
    signal(SIGSTOP, sig_handler);
    signal(SIGTRAP, sig_handler);
    signal(SIGCHLD, sig_handler);
    signal(SIGCONT, sig_handler);
    signal(SIGHUP, sig_handler);

    if (pid == 0) {
        // child
        int fd = open("/dev/null", O_RDWR);
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        close(fd);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[2], &argv[2]);
        printf("Exec error: %s\n", strerror(errno));
    } else {
        int status;
        fprintf(stderr, "PID: %d\n", pid);
        wait(&status);
        ptrace(PTRACE_SETOPTIONS, pid, 0,
               PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESYSGOOD);

        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        while (1) {
            pid = wait(&status);
            if (WIFEXITED(status) && pid == main_pid) {
                fprintf(stderr, "EXITED\n");
                break;
            }
//            if (WIFEXITED(status)) {
//                printf("PID %d exited status: %d!\n", pid, WEXITSTATUS(status));
//                sleep(1);
//            }
            int inject_signal = 0;
            if (WIFSTOPPED(status)) {
                // We can't use WSTOPSIG(status) as it cuts high bits.
                int signal = (status >> 8) & 0xFFFF;
                switch (signal) {
                    case SIGTRAP | 0x80: {
                        // SYSCALL TRAP as PTRACE_O_TRACESYSGOOD
                        struct ptrace_syscall_info *info = calloc(1, sizeof(struct ptrace_syscall_info));
                        ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(struct ptrace_syscall_info), info);
                        if (info->op == PTRACE_SYSCALL_INFO_ENTRY) {
                            store(pid, info);
                        }
                        if (info->op == PTRACE_SYSCALL_INFO_EXIT) {
                            struct ptrace_syscall_info *entry = fetch(pid);
                            handle_syscall(pid, entry, info);
                            free(info);
                        }
                    }
                        break;
                    case SIGTRAP: {
                        // Ordinary TRAP
//                        printf("SIGTRAP\n");
                        inject_signal = signal;
                    }
                        break;
                    case SIGTRAP | (PTRACE_EVENT_FORK << 8): {
//                        printf("SIGTRAP FORK\n");
                    }
                        break;
                    case SIGTRAP | (PTRACE_EVENT_VFORK << 8): {
//                        printf("SIGTRAP VFORK\n");
                    }
                        break;
                    case SIGTRAP | (PTRACE_EVENT_CLONE << 8): {
//                        printf("SIGTRAP CLONE\n");
                    }
                        break;
                    case SIGTRAP | (PTRACE_EVENT_EXEC << 8): {
//                        printf("SIGTRAP EXEC\n");
                    }
                        break;
                    case SIGTRAP | (PTRACE_EVENT_EXIT << 8): {
//                        printf("SIGTRAP EXIT\n");
                    }
                        break;
                    default:
                        //printf("SIGNAL %.2X\n", signal);
                        inject_signal = signal;
                        break;
                }
            }
            ptrace(PTRACE_SYSCALL, pid, 0, inject_signal);
        }
    }
}
