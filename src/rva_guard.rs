use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::api;

const RVA_IOUTIL_DELETE_FILE: usize = 0x625282B;

const RVA_DELETE_BY_GROUP: usize = 0x6263290;

const RVA_FINALLY1: usize = 0x6265B29;

static ORIG_IOUTIL: AtomicUsize = AtomicUsize::new(0);
static ORIG_FINALLY: AtomicUsize = AtomicUsize::new(0);
static HITS: AtomicU64 = AtomicU64::new(0);

pub fn hits() -> u64 {
    HITS.load(Ordering::Relaxed)
}

pub fn reset() {
    HITS.store(0, Ordering::Relaxed);
}

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
}

fn game_assembly_base() -> usize {
    unsafe {
        let n: Vec<u16> = "GameAssembly.dll\0".encode_utf16().collect();
        GetModuleHandleW(n.as_ptr()) as usize
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
        if t.is_null() {
            None
        } else {
            Some(t as usize)
        }
    }
}

extern "C" fn ioutil_delete_file(a0: *mut c_void, a1: *mut c_void, a2: *mut c_void, a3: *mut c_void) -> i32 {
    let n = HITS.fetch_add(1, Ordering::Relaxed);
    if n < 20 {
        let s = describe(a0);
        let s1 = describe(a1);
        api::log_warn(&format!(
            "[cleanup] IOUtil.DeleteFile 调用 #{} a0={} a1={}",
            n + 1,
            s,
            s1
        ));
    }
    if crate::should_block() {
        
        return 0;
    }
    type F = extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> i32;
    let f: F = unsafe { std::mem::transmute(ORIG_IOUTIL.load(Ordering::Relaxed)) };
    f(a0, a1, a2, a3)
}

fn describe(p: *mut c_void) -> String {
    if p.is_null() {
        return "null".into();
    }
    unsafe {
        
        let len_ptr = (p as *const u8).add(0x10) as *const i32;
        let len = *len_ptr;
        if len > 0 && len < 512 {
            let chars = (p as *const u8).add(0x14) as *const u16;
            let s: Vec<u16> = (0..len as isize).map(|i| *chars.offset(i)).collect();
            let text = String::from_utf16_lossy(&s);
            if text.chars().all(|c| !c.is_control()) {
                return text;
            }
        }
        format!("{:#x}", p as usize)
    }
}

pub fn install() {
    let base = game_assembly_base();
    if base == 0 {
        api::log_error("rva_guard: GameAssembly 基址拿不到");
        return;
    }
    api::log_info(&format!("rva_guard: GameAssembly base = {:#x}", base));

    let mut ok = 0;

    let addr = base + RVA_IOUTIL_DELETE_FILE;
    if let Some(t) = hook_at(addr, ioutil_delete_file as *const () as usize) {
        ORIG_IOUTIL.store(t, Ordering::SeqCst);
        ok += 1;
        api::log_info(&format!(
            "rva_guard: hooked Cyan.Utility.IOUtil::DeleteFile @ {:#x}",
            addr
        ));
    } else {
        api::log_warn("rva_guard: IOUtil.DeleteFile hook 失败");
    }

    api::log_info(&format!("rva_guard: 共挂 {} 个 RVA hook", ok));
}
