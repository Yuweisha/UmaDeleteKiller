use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::api;

const PATTERN: &[Option<u8>] = &[
    Some(0x48), Some(0x89), Some(0x5C), Some(0x24), Some(0x08),
    Some(0x48), Some(0x89), Some(0x6C), Some(0x24), Some(0x10),
    Some(0x48), Some(0x89), Some(0x74), Some(0x24), Some(0x18),
    Some(0x48), Some(0x89), Some(0x7C), Some(0x24), Some(0x20),
    Some(0x41), Some(0x56),
    Some(0x48), Some(0x83), Some(0xEC), Some(0x20),
    Some(0x80), Some(0x3D), Some(0xF1), None, None, None, None,
    Some(0x49), Some(0x8B), Some(0xD9),
    Some(0x49), Some(0x8B), Some(0xF0),
    Some(0x44), Some(0x8B), Some(0xF2),
];

static FOUND: AtomicUsize = AtomicUsize::new(0);
static HITS: AtomicU64 = AtomicU64::new(0);
static ORIG: AtomicUsize = AtomicUsize::new(0);

pub fn hits() -> u64 {
    HITS.load(Ordering::Relaxed)
}

pub fn reset() {
    HITS.store(0, Ordering::Relaxed);
}

pub fn found_addr() -> usize {
    FOUND.load(Ordering::Relaxed)
}

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
}

fn ga_base() -> usize {
    unsafe {
        let n: Vec<u16> = "GameAssembly.dll\0".encode_utf16().collect();
        GetModuleHandleW(n.as_ptr()) as usize
    }
}

fn scan(base: usize) -> usize {
    if base == 0 {
        return 0;
    }
    unsafe {
        
        let dos = base as *const u8;
        if *dos != b'M' || *dos.add(1) != b'Z' {
            return 0;
        }
        let e_lfanew = *(dos.add(0x3C) as *const i32) as usize;
        let nt = dos.add(e_lfanew);
        if *(nt as *const u32) != 0x0000_4550 {
            return 0; 
        }
        
        let opt = nt.add(0x18);
        let size_of_image = *(opt.add(0x38) as *const u32) as usize;

        let plen = PATTERN.len();
        if size_of_image <= plen {
            return 0;
        }

        
        let mut off = 0x1000usize; 
        while off + plen < size_of_image {
            let p = base + off;
            let mut ok = true;
            for (j, pat) in PATTERN.iter().enumerate() {
                if let Some(b) = pat {
                    if *((p + j) as *const u8) != *b {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                return p;
            }
            off += 1;
        }
        0
    }
}

fn hook_at(addr: usize, detour: usize) -> Option<usize> {
    if addr == 0 {
        return None;
    }
    unsafe {
        let a = api::api()?;
        let i = api::interceptor();
        if i.is_null() {
            return None;
        }
        let t = (a.interceptor_hook)(i, addr as *mut c_void, detour as *mut c_void);
        if t.is_null() { None } else { Some(t as usize) }
    }
}

extern "C" fn delete_by_group(
    this: *mut c_void,
    a0: *mut c_void,
    a1: *mut c_void,
    a2: *mut c_void,
) -> *mut c_void {
    let n = HITS.fetch_add(1, Ordering::Relaxed);
    if n < 20 {
        api::log_warn(&format!(
            "[cleanup] DeleteFilesByAnyGroupAsync 命中 #{} this={:#x}",
            n + 1, this as usize
        ));
    }
    if crate::should_block() {
        return std::ptr::null_mut();
    }
    type F = extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> *mut c_void;
    let f: F = unsafe { std::mem::transmute(ORIG.load(Ordering::Relaxed)) };
    f(this, a0, a1, a2)
}

pub fn install() {
    let base = ga_base();
    if base == 0 {
        api::log_error("sig_guard: GameAssembly 基址拿不到");
        return;
    }

    let addr = scan(base);
    if addr == 0 {
        api::log_error("sig_guard: 特征码未命中（游戏版本可能变了）");
        return;
    }

    FOUND.store(addr, Ordering::SeqCst);
    api::log_info(&format!(
        "sig_guard: 特征码命中 DeleteFilesByAnyGroupAsync @ {:#x} (rva 0x{:X})",
        addr,
        addr - base
    ));

    if let Some(t) = hook_at(addr, delete_by_group as *const () as usize) {
        ORIG.store(t, Ordering::SeqCst);
        api::log_info("sig_guard: hook 成功");
    } else {
        api::log_warn("sig_guard: hook 失败");
    }
}
