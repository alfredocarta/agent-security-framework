import docker
import json
import logging

logger = logging.getLogger(__name__)

_SECCOMP_PROFILE = json.dumps({
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
    "syscalls": [
        {"names": [
            "read", "write", "open", "openat", "close", "stat", "fstat",
            "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
            "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl",
            "pread64", "pwrite64", "readv", "writev", "access", "pipe",
            "select", "sched_yield", "mremap", "msync", "mincore", "madvise",
            "dup", "dup2", "nanosleep", "getitimer", "alarm", "setitimer",
            "getpid", "exit", "wait4", "kill", "uname", "fcntl", "flock",
            "fsync", "fdatasync", "truncate", "ftruncate", "getdents",
            "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir",
            "creat", "link", "unlink", "symlink", "readlink", "chmod",
            "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday",
            "getrlimit", "getrusage", "sysinfo", "times", "getuid", "getgid",
            "setuid", "setgid", "geteuid", "getegid", "getppid", "getpgrp",
            "setsid", "setreuid", "setregid", "getgroups", "setgroups",
            "rt_sigsuspend", "sigaltstack", "arch_prctl", "setrlimit",
            "sync", "gettid", "set_thread_area", "futex", "set_tid_address",
            "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group",
            "epoll_wait", "epoll_ctl", "tgkill", "set_robust_list",
            "get_robust_list", "splice", "eventfd2", "epoll_create1",
            "dup3", "pipe2", "prlimit64", "getrandom"
        ], "action": "SCMP_ACT_ALLOW"}
    ]
})

class ToolSandbox:
    def __init__(self, image="python:3.11-alpine"):
        self.image = image
        try:
            self.client = docker.from_env()
        except Exception as e:
            logger.warning(f"Docker not available: {e}")
            self.client = None

    def execute(self, code: str) -> str:
        if not self.client:
            raise RuntimeError("Docker not available for sandboxing.")

        try:
            container_logs = self.client.containers.run(
                self.image,
                command=["python", "-c", code],
                network_disabled=True,
                remove=True,
                mem_limit="128m",
                cpu_quota=50000,
                pids_limit=50,
                read_only=True,
                security_opt=[
                    "no-new-privileges:true",
                    f"seccomp={_SECCOMP_PROFILE}",
                ],
                cap_drop=["ALL"],
                user="nobody",
                stdout=True,
                stderr=True,
                environment={"ASF_SANDBOX": "true"}
            )
            return container_logs.decode("utf-8").strip()
        except docker.errors.ContainerError as e:
            return f"Sandbox Error: {e.stderr.decode('utf-8').strip()}"
        except Exception as e:
            return f"Execution Failed: {str(e)}"
