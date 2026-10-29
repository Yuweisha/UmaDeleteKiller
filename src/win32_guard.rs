use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::api;

static ORIG_W: AtomicUsize = AtomicUsize::new(0);
static ORIG_A: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicU64 = AtomicU64::new(0);
static BLOCKED: AtomicU64 = AtomicU64::new(0);

pub fn blocked_count() -> u64 {
    BLOCKED.load(Ordering::Relaxed)
}

pub fn reset_count() {
    SEEN.store(0, Ordering::Relaxed);
    BLOCKED.store(0, Ordering::Relaxed);
}

fn is_asset(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    l.contains("persistent\\dat\\") || l.contains("persistent/dat/")
}

fn report(path: &str, block: bool) {
    let tag = if block {
        let n = BLOCKED.fetch_add(1, Ordering::Relaxed);
        if n >= 12 {
            return;
        }
        "已拦截删除"
    } else {
        let n = SEEN.fetch_add(1, Ordering::Relaxed);
        if n >= 30 {
            return;
        }
        "删除请求（未拦截）"
    };

    let stack = capture_stack();
    let msg = format!("[cleanup] {}: {}\n{}", tag, path, stack);
    if block {
        api::log_warn(&msg);
    } else {
        api::log_info(&msg);
    }
}

const MAX_FRAMES: usize = 62;

#[link(name = "ntdll")]
extern "system" {
    fn RtlCaptureStackBackTrace(
        frames_to_skip: u32,
        frames_to_capture: u32,
        back_trace: *mut *mut std::ffi::c_void,
        back_trace_hash: *mut u32,
    ) -> u16;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut std::ffi::c_void;
    fn GetCurrentProcess() -> *mut std::ffi::c_void;
    fn GetModuleFileNameW(module: *mut std::ffi::c_void, buf: *mut u16, size: u32) -> u32;
}

#[link(name = "psapi")]
extern "system" {
    fn GetModuleInformation(
        process: *mut std::ffi::c_void,
        module: *mut std::ffi::c_void,
        info: *mut ModuleInfo,
        size: u32,
    ) -> i32;
}

#[repr(C)]
#[derive(Default)]
struct ModuleInfo {
    base: *mut std::ffi::c_void,
    size: u32,
    entry: *mut std::ffi::c_void,
}

fn game_assembly_range() -> (usize, usize) {
    unsafe {
        let name: Vec<u16> = "GameAssembly.dll\0".encode_utf16().collect();
        let h = GetModuleHandleW(name.as_ptr());
        if h.is_null() {
            return (0, 0);
        }
        let mut info = ModuleInfo::default();
        if GetModuleInformation(GetCurrentProcess(), h, &mut info, std::mem::size_of::<ModuleInfo>() as u32) == 0 {
            return (0, 0);
        }
        (info.base as usize, info.size as usize)
    }
}

fn module_name(addr: usize) -> String {
    unsafe {
        let mut buf = [0u16; 260];
        let n = GetModuleFileNameW(addr as *mut _, buf.as_mut_ptr(), 260);
        if n == 0 {
            return String::new();
        }
        let s = String::from_utf16_lossy(&buf[..n as usize]);
        s.rsplit(['\\', '/']).next().unwrap_or("").to_string()
    }
}

fn capture_stack() -> String {
    let mut frames = [std::ptr::null_mut(); MAX_FRAMES];
    let n = unsafe {
        RtlCaptureStackBackTrace(0, MAX_FRAMES as u32, frames.as_mut_ptr(), std::ptr::null_mut())
    } as usize;

    let (gbase, gsize) = game_assembly_range();
    let mut out = String::from("    调用栈（全量）:\n");

    for (i, f) in frames[..n].iter().enumerate() {
        let a = *f as usize;
        if a == 0 {
            continue;
        }
        if gbase != 0 && a >= gbase && a < gbase + gsize {
            out.push_str(&format!("      #{:<2} GameAssembly+0x{:X}\n", i, a - gbase));
        } else {
            out.push_str(&format!("      #{:<2} {}+0x{:X}\n", i, module_name(a), a));
        }
    }
    if n == 0 {
        out.push_str("      （栈不可用）\n");
    }
    out
}

type DelW = extern "system" fn(*const u16) -> i32;
extern "system" fn delete_file_w(path: *const u16) -> i32 {
    if path.is_null() {
        return 0;
    }
    let mut n = 0usize;
    unsafe {
        while n < 1024 && *path.add(n) != 0 {
            n += 1;
        }
        let wide = std::slice::from_raw_parts(path, n);
        let s = String::from_utf16_lossy(wide);
        if is_asset(&s) {
            report(&s, crate::should_block());
            if crate::should_block() {
                return 1; 
            }
        }
        let orig: DelW = std::mem::transmute(ORIG_W.load(Ordering::Relaxed));
        orig(path)
    }
}

type DelA = extern "system" fn(*const u8) -> i32;
extern "system" fn delete_file_a(path: *const u8) -> i32 {
    if path.is_null() {
        return 0;
    }
    let mut n = 0usize;
    unsafe {
        while n < 1024 && *path.add(n) != 0 {
            n += 1;
        }
        let bytes = std::slice::from_raw_parts(path, n);
        let s = String::from_utf8_lossy(bytes).into_owned();
        if is_asset(&s) {
            report(&s, crate::should_block());
            if crate::should_block() {
                return 1;
            }
        }
        let orig: DelA = std::mem::transmute(ORIG_A.load(Ordering::Relaxed));
        orig(path)
    }
}

#[link(name = "kernel32")]
extern "system" {
    fn GetProcAddress(m: *mut std::ffi::c_void, name: *const u8) -> *mut std::ffi::c_void;
}

fn addr_of(func: &str) -> usize {
    unsafe {
        let dll: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let h = GetModuleHandleW(dll.as_ptr());
        if h.is_null() {
            return 0;
        }
        let mut f = func.as_bytes().to_vec();
        f.push(0);
        GetProcAddress(h, f.as_ptr()) as usize
    }
}

fn hook(addr: usize, detour: usize) -> Option<usize> {
    if addr == 0 {
        return None;
    }
    unsafe {
        let a = api::api()?;
        let i = api::interceptor();
        if i.is_null() {
            return None;
        }
        let t = (a.interceptor_hook)(
            i,
            addr as *mut std::ffi::c_void,
            detour as *mut std::ffi::c_void,
        );
        if t.is_null() {
            None
        } else {
            Some(t as usize)
        }
    }
}

pub fn install() {
    let w = addr_of("DeleteFileW");
    let a = addr_of("DeleteFileA");

    let mut ok = 0;
    if let Some(t) = hook(w, delete_file_w as *const () as usize) {
        ORIG_W.store(t, Ordering::SeqCst);
        ok += 1;
        api::log_info(&format!("assetcleanupguard: hooked DeleteFileW @ {:#x}", w));
    } else {
        api::log_warn("assetcleanupguard: DeleteFileW hook 失败");
    }

    if let Some(t) = hook(a, delete_file_a as *const () as usize) {
        ORIG_A.store(t, Ordering::SeqCst);
        ok += 1;
        api::log_info(&format!("assetcleanupguard: hooked DeleteFileA @ {:#x}", a));
    } else {
        api::log_warn("assetcleanupguard: DeleteFileA hook 失败");
    }

    api::log_info(&format!(
        "assetcleanupguard: 共挂 {} 个 Win32 删除 API（dat 目录才拦）",
        ok
    ));
}
