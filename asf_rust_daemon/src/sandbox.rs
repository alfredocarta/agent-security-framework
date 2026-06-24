use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use uuid::Uuid;

const DEFAULT_IMAGE: &str = "python:3.11-alpine";

const SECCOMP_PROFILE: &str = r#"{"defaultAction": "SCMP_ACT_ERRNO", "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"], "syscalls": [{"names": ["read", "write", "open", "openat", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore", "madvise", "dup", "dup2", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "exit", "wait4", "kill", "uname", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "getuid", "getgid", "setuid", "setgid", "geteuid", "getegid", "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "rt_sigsuspend", "sigaltstack", "arch_prctl", "setrlimit", "sync", "gettid", "set_thread_area", "futex", "set_tid_address", "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "set_robust_list", "get_robust_list", "splice", "eventfd2", "epoll_create1", "dup3", "pipe2", "prlimit64", "getrandom"], "action": "SCMP_ACT_ALLOW"}]}"#;

pub struct ToolSandbox {
    image: String,
}

impl ToolSandbox {
    pub fn new(image: &str) -> Self {
        Self {
            image: image.to_string(),
        }
    }

    pub fn default() -> Self {
        Self::new(DEFAULT_IMAGE)
    }

    pub fn execute(&self, code: &str) -> Result<String, String> {
        ensure_docker_available()?;

        let seccomp_file = TempFile::new("asf-seccomp", "json")?;
        fs::write(&seccomp_file.path, SECCOMP_PROFILE)
            .map_err(|err| format!("Failed to write seccomp profile: {err}"))?;

        let output = Command::new("docker")
            .arg("run")
            .arg("--network")
            .arg("none")
            .arg("--rm")
            .arg("--memory")
            .arg("128m")
            .arg("--cpu-quota")
            .arg("50000")
            .arg("--pids-limit")
            .arg("50")
            .arg("--read-only")
            .arg("--cap-drop")
            .arg("ALL")
            .arg("--user")
            .arg("nobody")
            .arg("--security-opt")
            .arg("no-new-privileges:true")
            .arg("--security-opt")
            .arg(format!("seccomp={}", seccomp_file.path.display()))
            .arg("--env")
            .arg("ASF_SANDBOX=true")
            .arg(&self.image)
            .arg("python")
            .arg("-c")
            .arg(code)
            .output()
            .map_err(|err| match err.kind() {
                io::ErrorKind::NotFound => {
                    "Docker not available: docker not found on PATH".to_string()
                }
                _ => format!("Failed to execute docker: {err}"),
            })?;

        if !output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stderr).into_owned());
        }

        let mut combined = Vec::with_capacity(output.stdout.len() + output.stderr.len());
        combined.extend_from_slice(&output.stdout);
        combined.extend_from_slice(&output.stderr);
        Ok(String::from_utf8_lossy(&combined).into_owned())
    }
}

fn ensure_docker_available() -> Result<(), String> {
    Command::new("docker")
        .arg("--version")
        .output()
        .map(|_| ())
        .map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => "Docker not available: docker not found on PATH".to_string(),
            _ => format!("Docker not available: {err}"),
        })
}

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn new(prefix: &str, extension: &str) -> Result<Self, String> {
        let filename = format!("{prefix}-{}.{}", Uuid::new_v4(), extension);
        Ok(Self {
            path: env::temp_dir().join(filename),
        })
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
