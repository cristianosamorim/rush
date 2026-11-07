//! The process table on Linux: `/proc` supplies the list, stat, cmdline,
//! environment, descendants and descriptors. This is the Linux counterpart
//! of `internal/proc/proc_linux.go` in the Go implementation.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{Comms, Pid, Proc};

static HZ: OnceLock<u64> = OnceLock::new();
static PAGE: OnceLock<u64> = OnceLock::new();
static BOOT: OnceLock<Option<SystemTime>> = OnceLock::new();

#[derive(Clone, Copy)]
struct Stat {
    pid: Pid,
    ppid: Pid,
    state: u8,
    utime: u64,
    stime: u64,
    start_ticks: u64,
    comm_start: usize,
    comm_end: usize,
}

impl Stat {
    fn start(&self) -> SystemTime {
        let Some(boot) = boot_time() else {
            return UNIX_EPOCH;
        };
        let hz = ticks_per_second();
        let ns = (self.start_ticks as u128)
            .saturating_mul(1_000_000_000)
            .checked_div(hz as u128)
            .unwrap_or(0);
        boot.checked_add(Duration::from_nanos(ns.min(u64::MAX as u128) as u64))
            .unwrap_or(UNIX_EPOCH)
    }

    fn cpu_ns(&self) -> u64 {
        let hz = ticks_per_second();
        ((self.utime as u128 + self.stime as u128)
            .saturating_mul(1_000_000_000)
            .checked_div(hz as u128)
            .unwrap_or(0))
        .min(u64::MAX as u128) as u64
    }
}

/// The process table's `/proc` names and comm interner are kept between
/// samples. Listing `/proc` itself is cheap, while interning avoids retaining
/// one allocation per row on every screen refresh.
struct ProcCache {
    comms: Comms,
}

static CACHE: Mutex<Option<ProcCache>> = Mutex::new(None);

fn proc_dir(pid: Pid) -> PathBuf {
    PathBuf::from("/proc").join(pid.to_string())
}

fn parse_stat(pid: Pid, bytes: Vec<u8>) -> Option<(Stat, Vec<u8>)> {
    if pid <= 0 {
        return None;
    }
    let open = bytes.iter().position(|&b| b == b'(')?;
    let close = bytes.iter().rposition(|&b| b == b')')?;
    if close <= open || bytes.get(close + 1) != Some(&b' ') {
        return None;
    }
    let fields = bytes[close + 2..]
        .split(|&b| b == b' ')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    // fields[0] is state (field 3); ppid is field 4, utime 14, stime 15,
    // starttime 22.
    let ppid = parse_i32(fields.get(1)?)?;
    let utime = parse_u64(fields.get(11)?)?;
    let stime = parse_u64(fields.get(12)?)?;
    let start_ticks = parse_u64(fields.get(19)?)?;
    Some((
        Stat {
            pid,
            ppid,
            state: *fields.first()?.first()?,
            utime,
            stime,
            start_ticks,
            comm_start: open + 1,
            comm_end: close,
        },
        bytes,
    ))
}

fn read_stat(pid: Pid) -> Option<(Stat, Vec<u8>)> {
    if pid <= 0 {
        return None;
    }
    parse_stat(pid, fs::read(proc_dir(pid).join("stat")).ok()?)
}

fn parse_i32(bytes: &[u8]) -> Option<i32> {
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

fn parse_u64(bytes: &[u8]) -> Option<u64> {
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

fn ticks_per_second() -> u64 {
    *HZ.get_or_init(|| {
        // SAFETY: sysconf reads a process-wide constant and takes no pointers.
        let n = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        (n > 0).then_some(n as u64).unwrap_or(100)
    })
}

fn page_size() -> u64 {
    *PAGE.get_or_init(|| {
        // SAFETY: sysconf reads a process-wide constant and takes no pointers.
        let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        (n > 0).then_some(n as u64).unwrap_or(4096)
    })
}

fn boot_time() -> Option<SystemTime> {
    *BOOT.get_or_init(|| {
        let stat = fs::read_to_string("/proc/stat").ok()?;
        let secs = stat
            .lines()
            .find_map(|line| line.strip_prefix("btime "))?
            .trim()
            .parse::<u64>()
            .ok()?;
        Some(UNIX_EPOCH + Duration::from_secs(secs))
    })
}

fn comm_bytes<'a>(stat: &Stat, bytes: &'a [u8]) -> &'a [u8] {
    &bytes[stat.comm_start..stat.comm_end]
}

pub(super) fn list() -> Vec<Proc> {
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = cache.get_or_insert_with(|| ProcCache {
        comms: Comms::new(),
    });
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<Pid>() else {
            continue;
        };
        let Some((stat, raw)) = read_stat(pid) else {
            continue;
        };
        out.push(Proc {
            pid: stat.pid,
            ppid: stat.ppid,
            comm: cache.comms.get(comm_bytes(&stat, &raw)),
            start: stat.start(),
            ..Proc::default()
        });
    }
    out
}

fn rss(pid: Pid) -> Option<u64> {
    let b = fs::read_to_string(proc_dir(pid).join("statm")).ok()?;
    let pages = b.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    pages.checked_mul(page_size())
}

fn usage_of(pid: Pid) -> Option<(u64, u64, u64, Stat)> {
    let (stat, _) = read_stat(pid)?;
    Some((rss(pid)?, stat.cpu_ns(), stat.start_ticks, stat))
}

pub(super) fn fill_usage(p: &mut Proc) {
    if let Some((mem, cpu, _, _)) = usage_of(p.pid) {
        p.footprint = mem;
        p.cpu_time = Duration::from_nanos(cpu);
    }
}

fn split_nul(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

fn split_cmdline(bytes: &[u8]) -> Vec<String> {
    let mut fields = bytes.split(|&b| b == 0).collect::<Vec<_>>();
    if fields.last().is_some_and(|field| field.is_empty()) {
        fields.pop();
    }
    fields
        .into_iter()
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

pub(super) fn args(pid: Pid) -> Vec<String> {
    let Some((stat, _)) = read_stat(pid) else {
        return Vec::new();
    };
    if stat.state == b'Z' {
        return Vec::new();
    }
    fs::read(proc_dir(pid).join("cmdline"))
        .map(|bytes| split_cmdline(&bytes))
        .unwrap_or_default()
}

pub(super) fn env(pid: Pid) -> Vec<String> {
    readable_env(pid).unwrap_or_default()
}

pub(super) fn readable_env(pid: Pid) -> Option<Vec<String>> {
    let (stat, _) = read_stat(pid)?;
    if stat.state == b'Z' {
        return None;
    }
    Some(split_nul(&fs::read(proc_dir(pid).join("environ")).ok()?))
}

pub(super) fn comm(pid: Pid) -> Option<String> {
    let (stat, raw) = read_stat(pid)?;
    Some(String::from_utf8_lossy(comm_bytes(&stat, &raw)).into_owned())
}

pub(super) fn zombie(pid: Pid) -> bool {
    read_stat(pid).is_some_and(|(s, _)| s.state == b'Z')
}

pub(super) fn started(pid: Pid) -> Option<SystemTime> {
    read_stat(pid).map(|(s, _)| s.start())
}

/// A compact identity for [`super::Sampler`]: RSS, CPU nanoseconds and the
/// kernel's start-time ticks (which distinguish a reused pid).
pub(super) fn usage(pid: Pid) -> Option<(u64, u64, u64)> {
    let (mem, cpu, start, _) = usage_of(pid)?;
    Some((mem, cpu, start))
}

pub(super) fn children(pid: Pid, out: &mut Vec<Pid>) {
    out.clear();
    let task_dir = proc_dir(pid).join("task");
    let mut read_any = false;
    if let Ok(tasks) = fs::read_dir(task_dir) {
        for task in tasks.flatten() {
            let Ok(s) = fs::read_to_string(task.path().join("children")) else {
                continue;
            };
            read_any = true;
            out.extend(s.split_whitespace().filter_map(|p| p.parse::<Pid>().ok()));
        }
    }
    if read_any {
        out.retain(|&p| p > 0);
        out.sort_unstable();
        out.dedup();
        return;
    }
    // The task/children file can be hidden by a restrictive proc mount. A
    // table scan remains correct and keeps tree sampling useful in that case.
    out.extend(list().into_iter().filter(|p| p.ppid == pid).map(|p| p.pid));
}

pub(super) fn cwd(pid: Pid) -> Option<PathBuf> {
    fs::read_link(proc_dir(pid).join("cwd")).ok()
}

fn regular_link(path: &Path) -> Option<PathBuf> {
    let target = fs::read_link(path).ok()?;
    let metadata = fs::metadata(path).ok()?;
    metadata.file_type().is_file().then_some(target)
}

pub(super) fn fd_file(pid: Pid, fd: i32) -> Option<PathBuf> {
    (fd >= 0)
        .then(|| proc_dir(pid).join("fd").join(fd.to_string()))
        .and_then(|p| regular_link(&p))
}

pub(super) fn files(pid: Pid) -> Vec<(i32, PathBuf)> {
    let Ok(entries) = fs::read_dir(proc_dir(pid).join("fd")) else {
        return Vec::new();
    };
    let mut out = entries
        .flatten()
        .filter_map(|e| {
            let fd = e.file_name().to_str()?.parse::<i32>().ok()?;
            regular_link(&e.path()).map(|p| (fd, p))
        })
        .collect::<Vec<_>>();
    out.sort_unstable_by_key(|(fd, _)| *fd);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_stat_comm_with_spaces() {
        let raw = b"123 (name with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21";
        let (stat, bytes) = parse_stat(123, raw.to_vec()).unwrap();
        assert_eq!(stat.ppid, 1);
        assert_eq!(comm_bytes(&stat, &bytes), b"name with spaces");
    }

    #[test]
    fn cwd_and_files_are_read_for_self() {
        let pid = std::process::id() as Pid;
        assert!(cwd(pid).is_some());
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().canonicalize().unwrap();
        assert!(files(pid).iter().any(|(_, p)| p == &path));
    }
}
