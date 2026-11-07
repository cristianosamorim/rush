//! What the gate reads of the machine's memory, and lowering a process's
//! priority. Ported from internal/gate/sys_darwin.go:1-89,
//! sys_linux.go:1-63 and sys_other.go; Go's package variables Memory,
//! PressureLevel and MemoryLevel, which tests set, are the [`Machine`]
//! a [`crate::Gate`] is given.

/// What the gate reads of the machine.
pub trait Machine: Send + Sync {
    /// What the machine has: available (free, inactive and purgeable) and
    /// in all, in bytes; 0, 0 when it can't be read.
    fn memory(&self) -> (u64, u64);
    /// The kernel's memory pressure level: 1 normal, 2 warning, 4
    /// critical; 0 when it can't be read.
    fn pressure_level(&self) -> i32;
    /// The share of memory available, 0 to 100; -1 when it can't be read.
    fn memory_level(&self) -> i32;
}

/// This machine, as its kernel says.
#[derive(Clone, Copy, Debug, Default)]
pub struct Real;

impl Machine for Real {
    fn memory(&self) -> (u64, u64) {
        os::memory()
    }
    fn pressure_level(&self) -> i32 {
        os::pressure()
    }
    fn memory_level(&self) -> i32 {
        os::mem_level()
    }
}

/// Lowers pid's priority to nice n, never raising it: one already nicer
/// keeps its own.
pub fn renice(pid: i32, n: i32) {
    os::renice(pid, n)
}

/// The available bytes vm_stat's output says.
pub fn parse_vm_stat(s: &str) -> Option<u64> {
    let mut lines = s.split('\n');
    let first = lines.next().unwrap_or("");
    let mut page = 0u64;
    if let Some(i) = first.find("page size of ")
        && let Some(f) = first[i + "page size of ".len()..].split_whitespace().next()
    {
        page = f.parse().unwrap_or(0);
    }
    if page == 0 {
        return None;
    }
    let mut pages = 0u64;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        if matches!(k, "Pages free" | "Pages inactive" | "Pages purgeable") {
            let v = v.trim();
            pages = pages.saturating_add(v.strip_suffix('.').unwrap_or(v).parse::<u64>().ok()?);
        }
    }
    Some(pages.saturating_mul(page))
}

/// Sets errno to 0, so a call that can return -1 for real can be told
/// from one that failed.
fn clear_errno() {
    // SAFETY: errno is this thread's own.
    #[cfg(target_os = "macos")]
    unsafe {
        *libc::__error() = 0;
    }
    // SAFETY: errno is this thread's own.
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location() = 0;
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// pid's nice, as getpriority(2) says it; None when it can't be read.
#[allow(dead_code)]
fn priority(pid: i32) -> Option<i32> {
    clear_errno();
    // SAFETY: getpriority takes plain integers.
    let p = unsafe { libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t) };
    if p == -1 && errno() != 0 {
        return None;
    }
    Some(p)
}

#[cfg(target_os = "macos")]
mod os {
    use std::ffi::CString;

    fn sysctl<T: Default + Copy>(name: &str) -> Option<T> {
        let name = CString::new(name).ok()?;
        let mut v = T::default();
        let mut len = std::mem::size_of::<T>();
        // SAFETY: v is a T and len its size; the kernel writes at most len.
        let r = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                (&mut v as *mut T).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        (r == 0 && len == std::mem::size_of::<T>()).then_some(v)
    }

    /// What the machine has, available and in all, in bytes, as vm_stat
    /// counts it: free, inactive and purgeable pages are available. 0, 0
    /// when it can't be read.
    pub fn memory() -> (u64, u64) {
        let Some(total) = sysctl::<u64>("hw.memsize") else {
            return (0, 0);
        };
        let Ok(out) = std::process::Command::new("/usr/bin/vm_stat")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
        else {
            return (0, 0);
        };
        if !out.status.success() {
            return (0, 0);
        }
        match super::parse_vm_stat(&String::from_utf8_lossy(&out.stdout)) {
            Some(avail) => (avail, total),
            None => (0, 0),
        }
    }

    /// kern.memorystatus_vm_pressure_level: 1 normal, 2 warning, 4
    /// critical; 0 when it can't be read.
    pub fn pressure() -> i32 {
        sysctl::<u32>("kern.memorystatus_vm_pressure_level").map_or(0, |v| v as i32)
    }

    /// kern.memorystatus_level: the share of memory the kernel counts
    /// available, 0 to 100, as Activity Monitor's pressure graph has it;
    /// -1 when it can't be read. One sysctl, no fork, so it still reads
    /// when the machine is paging hard.
    pub fn mem_level() -> i32 {
        match sysctl::<u32>("kern.memorystatus_level") {
            Some(v) if v <= 100 => v as i32,
            _ => -1,
        }
    }

    pub fn renice(pid: i32, n: i32) {
        if super::priority(pid).is_some_and(|cur| cur >= n) {
            return;
        }
        // SAFETY: setpriority takes plain integers.
        unsafe {
            libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, n);
        }
    }
}

/// Parses Linux's `/proc/meminfo` values.  The kernel reports the fields in
/// KiB today, but accepting the other documented units keeps this parser
/// correct for procfs implementations which choose to spell them out.
#[cfg(target_os = "linux")]
pub fn parse_meminfo(s: &str) -> Option<(u64, u64)> {
    let mut total = None;
    let mut available = None;
    for line in s.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if !matches!(name, "MemTotal" | "MemAvailable") {
            continue;
        }
        let mut value = value.split_whitespace();
        let Some(n) = value.next().and_then(|n| n.parse::<u64>().ok()) else {
            continue;
        };
        let multiplier = match value.next().unwrap_or("kB") {
            "kB" => 1024,
            "MB" => 1024 * 1024,
            "GB" => 1024 * 1024 * 1024,
            "B" => 1,
            _ => continue,
        };
        let Some(bytes) = n.checked_mul(multiplier) else {
            continue;
        };
        match name.trim() {
            "MemTotal" => total = Some(bytes),
            "MemAvailable" => available = Some(bytes),
            _ => {}
        }
    }
    Some((available?, total?))
}

#[cfg(target_os = "linux")]
mod os {
    /// What `/proc/meminfo` says is available and in all, in bytes.
    pub fn memory() -> (u64, u64) {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| super::parse_meminfo(&s))
            .unwrap_or((0, 0))
    }

    /// Linux has no single pressure level matching Darwin's VM pressure
    /// sysctl.  The caller treats zero as unknown; memory_level still gives
    /// the useful `/proc/meminfo` availability share.
    pub fn pressure() -> i32 {
        0
    }

    pub fn mem_level() -> i32 {
        let (available, total) = memory();
        if total == 0 {
            return -1;
        }
        ((available as u128 * 100 / total as u128).min(100)) as i32
    }

    pub fn renice(pid: i32, n: i32) {
        // Linux keeps nice per thread, so include the agent's worker
        // threads. libc::getpriority already translates the raw syscall
        // result to the conventional -20..19 nice value.
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
            return;
        };
        for task in tasks.flatten() {
            let Ok(tid) = task.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            if super::priority(tid).is_some_and(|cur| cur >= n) {
                continue;
            }
            // SAFETY: setpriority takes plain integers.
            unsafe {
                libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, n);
            }
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod os {
    pub fn memory() -> (u64, u64) {
        (0, 0)
    }

    pub fn pressure() -> i32 {
        0
    }

    pub fn mem_level() -> i32 {
        -1
    }

    pub fn renice(pid: i32, n: i32) {
        if super::priority(pid).is_some_and(|cur| cur >= n) {
            return;
        }
        // SAFETY: setpriority takes plain integers.
        unsafe {
            libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use std::io::{Read, Write};
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    use std::process::Command;
    #[cfg(target_os = "linux")]
    use std::process::Stdio;
    #[cfg(target_os = "linux")]
    use std::sync::{Arc, Barrier, Condvar, Mutex};

    // sys_darwin_test.go TestParseVMStat
    #[cfg(target_os = "macos")]
    #[test]
    fn parses_vm_stat() {
        let out = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n\
            Pages free:                                   100.\nPages active:                                 999.\n\
            Pages inactive:                                 20.\nPages speculative:                              7.\n\
            Pages purgeable:                                 3.\n";
        assert_eq!(parse_vm_stat(out), Some(123 * 16384));
        assert_eq!(parse_vm_stat("nonsense"), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn renice_changes_a_child_process() {
        let mut child = Command::new("/bin/sleep").arg("60").spawn().unwrap();
        let pid = child.id() as i32;
        let before = priority(pid).unwrap();
        if before < 19 {
            renice(pid, before + 1);
            let after = priority(pid).unwrap();
            assert!(after > before, "child stayed at nice {before}, now {after}");
        }
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_meminfo() {
        let input = "MemTotal:       1024 kB\nMemAvailable:    256 kB\n";
        assert_eq!(parse_meminfo(input), Some((256 * 1024, 1024 * 1024)));
        assert_eq!(parse_meminfo("MemTotal: 1 kB"), None);
    }

    #[cfg(target_os = "linux")]
    fn task_nice(pid: i32, tid: i32) -> Option<i32> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/stat")).ok()?;
        let close = stat.rfind(')')?;
        stat.get(close + 2..)?
            .split_whitespace()
            .nth(16)?
            .parse()
            .ok()
    }

    #[cfg(target_os = "linux")]
    fn all_task_nice(pid: i32) -> Vec<(i32, i32)> {
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
            return Vec::new();
        };
        let mut out: Vec<_> = tasks
            .flatten()
            .filter_map(|task| {
                let tid = task.file_name().to_string_lossy().parse().ok()?;
                Some((tid, task_nice(pid, tid)?))
            })
            .collect();
        out.sort_unstable_by_key(|(tid, _)| *tid);
        out
    }

    #[cfg(target_os = "linux")]
    fn wait_task_nice(pid: i32, tid: i32) -> Option<i32> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(nice) = task_nice(pid, tid) {
                return Some(nice);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::yield_now();
        }
    }

    // A child-only test entry point.  The parent test starts this test binary
    // with the environment marker, then renices it while these worker threads
    // are held alive.
    #[cfg(target_os = "linux")]
    #[test]
    fn renice_child_helper() {
        if std::env::var_os("RUSH_GATE_RENICE_HELPER").is_none() {
            return;
        }
        let Some(ready) = std::env::var_os("RUSH_GATE_RENICE_READY") else {
            return;
        };
        let ready = std::path::PathBuf::from(ready);
        let barrier = Arc::new(Barrier::new(3));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let tids = Arc::new(Mutex::new(Vec::new()));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let barrier = barrier.clone();
            let release = release.clone();
            let tids = tids.clone();
            workers.push(std::thread::spawn(move || {
                // SAFETY: gettid takes no pointers and returns this thread's
                // stable kernel id.
                let tid = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
                tids.lock().unwrap().push(tid);
                barrier.wait();
                let (lock, wake) = &*release;
                let mut done = lock.lock().unwrap();
                while !*done {
                    done = wake.wait(done).unwrap();
                }
            }));
        }
        barrier.wait();
        let tids = tids.lock().unwrap();
        let ids = tids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let ready_tmp = ready.with_extension("tmp");
        std::fs::write(&ready_tmp, ids).unwrap();
        std::fs::rename(ready_tmp, ready).unwrap();
        drop(tids);

        let mut byte = [0u8; 1];
        std::io::stdin().read_exact(&mut byte).unwrap();
        let (lock, wake) = &*release;
        *lock.lock().unwrap() = true;
        wake.notify_all();
        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn renice_changes_all_child_threads_without_touching_another_process() {
        let temp = tempfile::tempdir().unwrap();
        let ready = temp.path().join("ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("renice_child_helper")
            .env("RUSH_GATE_RENICE_HELPER", "1")
            .env("RUSH_GATE_RENICE_READY", &ready)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let child_pid = child.id() as i32;
        let ready_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !ready.exists() && std::time::Instant::now() < ready_deadline {
            std::thread::yield_now();
        }
        if !ready.exists() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("renice helper did not become ready");
        }
        let worker_tids: Vec<i32> = std::fs::read_to_string(&ready)
            .unwrap()
            .split(',')
            .filter_map(|tid| tid.parse().ok())
            .collect();
        let before = all_task_nice(child_pid);

        let mut unrelated = Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let unrelated_pid = unrelated.id() as i32;
        let unrelated_before = wait_task_nice(unrelated_pid, unrelated_pid);
        let target = before
            .iter()
            .map(|(_, nice)| *nice)
            .min()
            .and_then(|nice| (nice < 19).then_some(nice + 1));
        let Some(target) = target else {
            let _ = child.stdin.take().unwrap().write_all(b"x");
            let _ = child.wait();
            let _ = unrelated.kill();
            let _ = unrelated.wait();
            return;
        };

        renice(child_pid, target);
        let after = all_task_nice(child_pid);
        let workers_raised = !worker_tids.is_empty()
            && worker_tids
                .iter()
                .all(|tid| task_nice(child_pid, *tid).is_some_and(|nice| nice >= target));
        let all_raised = !after.is_empty() && after.iter().all(|(_, nice)| *nice >= target);
        let unrelated_after = wait_task_nice(unrelated_pid, unrelated_pid);

        let _ = child.stdin.take().unwrap().write_all(b"x");
        let child_status = child.wait().unwrap();
        let _ = unrelated.kill();
        let _ = unrelated.wait();

        assert!(
            child_status.success(),
            "renice helper failed: {child_status}"
        );
        assert!(workers_raised, "worker thread priorities were not raised");
        assert!(all_raised, "not every child thread was reniced: {after:?}");
        assert_eq!(unrelated_after, unrelated_before);
    }

    #[test]
    fn reads_this_machine() {
        let (avail, total) = Real.memory();
        assert!(total > 0 && avail <= total, "{avail} of {total}");
        assert!((-1..=100).contains(&Real.memory_level()));
    }
}
