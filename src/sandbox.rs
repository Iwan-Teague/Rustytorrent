//! Linux seccomp sandbox (C2 from the security roadmap).
//!
//! Installs a BPF syscall filter that whitelists only the kernel
//! entrypoints rustytorrent actually uses. Anything outside the list
//! is `SECCOMP_RET_KILL_PROCESS` — the kernel terminates the whole
//! process via SIGSYS instead of returning to the caller. Defense in
//! depth: even if an exploit lands in our address space (e.g. a
//! corrupt-stream bug in the bencode parser turns into RCE), the
//! attacker can't pivot via syscalls outside this whitelist.
//! `ptrace`, `init_module`, `kexec_load`, `mount`, `swapon`, and a
//! long tail of other privilege-escalation entrypoints are all gone.
//!
//! ## Scope
//!
//! Linux x86_64 only today. Other platforms (macOS, Windows, Linux
//! ARM64) report unsupported. The audit-architecture check in the
//! filter rejects 32-bit syscalls on a 64-bit kernel — a common
//! evasion trick — so the whitelist is tight against the x86_64
//! syscall numbering only.
//!
//! ## When the sandbox engages
//!
//! Late in engine startup, just before entering the main `select!`
//! loop. By that point the noisy init has finished: files are open,
//! the listener is bound, the initial DNS-resolved tracker announce
//! has gone out, the DHT bootstrap has run, MSE DH keys are derived.
//! Anything we still need to do during the download — file I/O,
//! socket I/O, futex, mmap, signal handling, timer / epoll
//! servicing — has to be in the whitelist. If the kernel kills the
//! process on a denied syscall, the panic message in syslog (look
//! for "audit: type=1326" or `dmesg | grep SIGSYS`) names the
//! offending NR.
//!
//! ## Updating the whitelist
//!
//! The list is hand-curated against a tokio-1.x runtime, rustls
//! TLS, and our hand-written network code. A tokio version bump
//! can add syscalls (recent additions: `clone3`, `close_range`,
//! `pidfd_*`). If the binary starts dying on launch with SIGSYS
//! after a dep bump, run `strace -ce` against an instrumented build
//! to enumerate the new entries, then add them to
//! `allowed_syscalls`. The whitelist is opt-in via `--sandbox`, so
//! the cost of a stale list is "user can't use --sandbox until we
//! refresh it," not "everyone breaks."
//!
//! ## Why hand-rolled BPF and not a crate
//!
//! The dependency hygiene rule: no BitTorrent-specific deps, and
//! crypto/runtime ones only when they're genuinely irreplaceable.
//! The filter is ~80 instructions of fixed-shape BPF; encoding it
//! by hand is ~50 lines and lets us own the entire surface.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use linux_x86_64::engage;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn engage() -> crate::error::Result<()> {
    Err(crate::error::Error::Network(
        "--sandbox requires Linux x86_64 (other platforms have no implementation today)".into(),
    ))
}

/// Whether the current build target supports the sandbox. Lets the
/// engine print a "sandbox: skipped on this platform" message in
/// the non-Linux build instead of trying to engage and failing.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const SUPPORTED: bool = true;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub const SUPPORTED: bool = false;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_x86_64 {
    use crate::error::{Error, Result};

    // BPF instruction codes (linux/filter.h).
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    // seccomp return actions (linux/seccomp.h).
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

    // BPF input field offsets inside `struct seccomp_data`.
    const NR_OFFSET: u32 = 0;
    const ARCH_OFFSET: u32 = 4;

    // x86_64 audit arch (linux/audit.h: AUDIT_ARCH_X86_64).
    const AUDIT_ARCH_X86_64: u32 = 0xC000003E;

    // seccomp(2) opmode + flags.
    const SECCOMP_SET_MODE_FILTER: u32 = 1;
    /// Apply the filter to every thread in the current thread group,
    /// not just the caller. tokio spawns worker threads at startup;
    /// without TSYNC the workers would still be unsandboxed.
    const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1;

    /// BPF jump distances are encoded in `u8`. With a default-deny
    /// whitelist the jump from each JEQ to the shared ALLOW return
    /// is `n - i` instructions, so the longest jump is `n`. Cap the
    /// allowed-syscall list at this length to keep every JEQ
    /// representable.
    const MAX_ALLOWED: usize = 255;

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    /// Curated list of syscalls our binary needs in steady-state
    /// (post-startup). Keep grouped by purpose so a future reviewer
    /// can audit each block without grepping. See the module docs for
    /// the "updating the whitelist" workflow.
    fn allowed_syscalls() -> Vec<u32> {
        let nrs: &[libc::c_long] = &[
            // Core I/O
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_pread64,
            libc::SYS_pwrite64,
            libc::SYS_close,
            libc::SYS_openat,
            libc::SYS_lseek,
            libc::SYS_fsync,
            libc::SYS_fdatasync,
            libc::SYS_ftruncate,
            libc::SYS_mkdirat,
            libc::SYS_unlinkat,
            libc::SYS_newfstatat,
            libc::SYS_fstat,
            libc::SYS_statx,
            libc::SYS_readlinkat,
            libc::SYS_getdents64,
            libc::SYS_dup,
            libc::SYS_dup3,
            // Memory
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_mprotect,
            libc::SYS_brk,
            libc::SYS_mremap,
            libc::SYS_madvise,
            // Threads / scheduler / process
            libc::SYS_futex,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_sigaltstack,
            libc::SYS_set_robust_list,
            libc::SYS_get_robust_list,
            libc::SYS_sched_getaffinity,
            libc::SYS_sched_yield,
            libc::SYS_set_tid_address,
            libc::SYS_restart_syscall,
            libc::SYS_gettid,
            libc::SYS_tgkill,
            libc::SYS_getpid,
            libc::SYS_prlimit64,
            libc::SYS_getrlimit,
            libc::SYS_uname,
            libc::SYS_arch_prctl,
            // Time
            libc::SYS_clock_gettime,
            libc::SYS_clock_nanosleep,
            libc::SYS_nanosleep,
            libc::SYS_timerfd_create,
            libc::SYS_timerfd_settime,
            // Random
            libc::SYS_getrandom,
            // Eventfd / pipe / epoll (tokio's reactor)
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_wait,
            libc::SYS_epoll_pwait,
            libc::SYS_eventfd2,
            libc::SYS_pipe2,
            // Networking — sockets + I/O
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_setsockopt,
            libc::SYS_getsockopt,
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
            libc::SYS_shutdown,
            // fcntl/ioctl drive nonblocking flags + odd things tokio asks for
            libc::SYS_fcntl,
            libc::SYS_ioctl,
        ];
        nrs.iter().map(|&n| n as u32).collect()
    }

    /// Encode the BPF program.
    ///
    /// Layout:
    /// ```text
    /// 0: LD W ABS [ARCH_OFFSET]            ; load audit arch
    /// 1: JEQ AUDIT_ARCH_X86_64, +1, 0      ; arch matches → skip kill
    /// 2: RET KILL_PROCESS                  ; wrong arch (e.g. 32-bit syscall) → die
    /// 3: LD W ABS [NR_OFFSET]              ; load syscall nr
    /// 4..4+n: JEQ nrs[i], +(n-i), 0        ; match → jump to ALLOW
    /// 4+n: RET KILL_PROCESS                ; fell through whitelist → die
    /// 5+n: RET ALLOW                       ; jump target for any match
    /// ```
    fn build_filter(allowed: &[u32]) -> Vec<SockFilter> {
        assert!(
            allowed.len() <= MAX_ALLOWED,
            "seccomp whitelist exceeds u8 jump range ({} > {})",
            allowed.len(),
            MAX_ALLOWED
        );
        let n = allowed.len() as u32;
        let mut f = Vec::with_capacity(allowed.len() + 5);
        f.push(SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: ARCH_OFFSET,
        });
        f.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: AUDIT_ARCH_X86_64,
        });
        f.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        });
        f.push(SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: NR_OFFSET,
        });
        for (i, &nr) in allowed.iter().enumerate() {
            // ALLOW return sits at index `5+n` (0-based). From a JEQ
            // at index `4+i`, the next instruction is `5+i`, so the
            // jt distance to ALLOW is `(5+n) - (5+i) = n - i`.
            f.push(SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: (n - i as u32) as u8,
                jf: 0,
                k: nr,
            });
        }
        f.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        });
        f.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        });
        f
    }

    /// Install the seccomp filter and lock the no-new-privs bit so
    /// the kernel will keep enforcing it across exec.
    pub fn engage() -> Result<()> {
        let allowed = allowed_syscalls();
        let filter = build_filter(&allowed);

        // PR_SET_NO_NEW_PRIVS = 38 — required for non-root processes
        // to install a seccomp filter. Without it the kernel rejects
        // the install to prevent a sandboxed process from escalating
        // via setuid binaries discovered later. We bake this in.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(Error::Network(format!(
                "sandbox: PR_SET_NO_NEW_PRIVS failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let prog = SockFprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };
        // SAFETY: `prog.filter` points into `filter`, which lives
        // through the syscall return below. The kernel copies the
        // program out before returning, so it's safe to drop `filter`
        // afterwards.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER as libc::c_long,
                SECCOMP_FILTER_FLAG_TSYNC as libc::c_long,
                &prog as *const _ as libc::c_long,
            )
        };
        if rc != 0 {
            return Err(Error::Network(format!(
                "sandbox: seccomp install failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // Hold the filter alive until past the syscall return.
        // Once the kernel has copied it the storage can drop normally.
        drop(filter);

        tracing::info!(
            target: "sandbox",
            allowed = allowed.len(),
            "seccomp filter installed (default-deny whitelist)"
        );
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn filter_has_expected_shape() {
            let nrs: Vec<u32> = (10..14).collect();
            let f = build_filter(&nrs);
            // 4 prelude + 4 JEQ + 2 epilogue (RET KILL + RET ALLOW) = 10
            assert_eq!(f.len(), 4 + nrs.len() + 2);
            // First instruction loads from ARCH_OFFSET (= 4).
            assert_eq!(f[0].k, ARCH_OFFSET);
            // Second instruction is the arch JEQ.
            assert_eq!(f[1].k, AUDIT_ARCH_X86_64);
            // Final instruction is RET ALLOW.
            assert_eq!(f.last().unwrap().k, SECCOMP_RET_ALLOW);
            // Penultimate is RET KILL_PROCESS.
            assert_eq!(f[f.len() - 2].k, SECCOMP_RET_KILL_PROCESS);
        }

        #[test]
        fn first_jeq_jt_reaches_allow() {
            let nrs: Vec<u32> = (100..104).collect();
            let f = build_filter(&nrs);
            // Layout: [LD arch, JEQ arch, RET kill, LD nr, JEQ nr0, JEQ nr1, JEQ nr2, JEQ nr3, RET kill, RET allow]
            // ALLOW at index 9. First JEQ at index 4. Distance after the
            // JEQ (PC = 4+1 = 5) to ALLOW = 9 - 5 = 4 instructions.
            assert_eq!(f[4].jt, 4);
            // Last JEQ at index 7; distance after it (PC = 8) to
            // ALLOW = 9 - 8 = 1.
            assert_eq!(f[7].jt, 1);
        }

        #[test]
        fn allowed_syscalls_includes_read_write_futex() {
            let allowed = allowed_syscalls();
            assert!(allowed.contains(&(libc::SYS_read as u32)));
            assert!(allowed.contains(&(libc::SYS_write as u32)));
            assert!(allowed.contains(&(libc::SYS_futex as u32)));
            assert!(allowed.contains(&(libc::SYS_openat as u32)));
        }

        #[test]
        fn allowed_syscalls_under_jump_cap() {
            // The whitelist must stay short enough for u8 BPF jumps.
            // If this trips, either prune or chain through an
            // intermediate ALLOW return.
            assert!(
                allowed_syscalls().len() <= MAX_ALLOWED,
                "whitelist exceeded MAX_ALLOWED ({}) — chain via intermediate ALLOW",
                MAX_ALLOWED
            );
        }

        #[test]
        fn allowed_syscalls_excludes_dangerous_ones() {
            // Sanity check the negative space — these must NOT be
            // in the whitelist or the sandbox is useless.
            let allowed = allowed_syscalls();
            for nr in [
                libc::SYS_ptrace,
                libc::SYS_init_module,
                libc::SYS_kexec_load,
                libc::SYS_mount,
                libc::SYS_swapon,
            ] {
                assert!(
                    !allowed.contains(&(nr as u32)),
                    "dangerous syscall {nr} present in whitelist"
                );
            }
        }
    }
}
