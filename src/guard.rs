use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::api;

static ORIG_DELETE_ALL: AtomicUsize = AtomicUsize::new(0);
static ORIG_DELETE_GROUP: AtomicUsize = AtomicUsize::new(0);
static ORIG_DELETE_FILES: AtomicUsize = AtomicUsize::new(0);
static BLOCKED: AtomicU64 = AtomicU64::new(0);

pub fn blocked_count() -> u64 {
    BLOCKED.load(Ordering::Relaxed)
}

pub fn reset_count() {
    BLOCKED.store(0, Ordering::Relaxed);
}

fn tick(kind: &str) {
    let n = BLOCKED.fetch_add(1, Ordering::Relaxed);
    if n < 20 {
        if crate::should_block() {
            api::log_warn(&format!("[cleanup] 拦截 {}", kind));
        } else {
            api::log_info(&format!("[cleanup] 检测到 {}（未拦截）", kind));
        }
    }
}

type Void0 = extern "C" fn(*mut c_void);
extern "C" fn delete_all_files(this: *mut c_void) {
    tick("DeleteAllFiles");
    if crate::should_block() {
        return;
    }
    let orig: Void0 = unsafe { std::mem::transmute(ORIG_DELETE_ALL.load(Ordering::Relaxed)) };
    orig(this)
}

type Ret3 = extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> *mut c_void;
extern "C" fn delete_by_group(this: *mut c_void, a1: *mut c_void, a2: *mut c_void, a3: *mut c_void) -> *mut c_void {
    tick("DeleteFilesByAnyGroupAsync");
    if crate::should_block() {
        return std::ptr::null_mut();
    }
    let orig: Ret3 = unsafe { std::mem::transmute(ORIG_DELETE_GROUP.load(Ordering::Relaxed)) };
    orig(this, a1, a2, a3)
}

type Ret2 = extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void;
extern "C" fn delete_files(this: *mut c_void, a1: *mut c_void, a2: *mut c_void) -> *mut c_void {
    tick("DeleteFilesAsync");
    if crate::should_block() {
        return std::ptr::null_mut();
    }
    let orig: Ret2 = unsafe { std::mem::transmute(ORIG_DELETE_FILES.load(Ordering::Relaxed)) };
    orig(this, a1, a2)
}

static ORIG_DELETE_ALL_ASYNC: AtomicUsize = AtomicUsize::new(0);
static ORIG_DATA_MGMT: AtomicUsize = AtomicUsize::new(0);

type Ret1 = extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;

extern "C" fn delete_all_async(this: *mut c_void, a1: *mut c_void) -> *mut c_void {
    tick("AssetManager.DeleteAllAsync");
    if crate::should_block() {
        return std::ptr::null_mut();
    }
    let orig: Ret1 = unsafe { std::mem::transmute(ORIG_DELETE_ALL_ASYNC.load(Ordering::Relaxed)) };
    orig(this, a1)
}

extern "C" fn data_management_async(this: *mut c_void, a1: *mut c_void) -> *mut c_void {
    tick("AssetManager.DataManagementAsync");
    if crate::should_block() {
        return std::ptr::null_mut();
    }
    let orig: Ret1 = unsafe { std::mem::transmute(ORIG_DATA_MGMT.load(Ordering::Relaxed)) };
    orig(this, a1)
}

fn get_class_of(image: *const api::Il2CppImage, ns: &str, name: &str) -> Option<*mut api::Il2CppClass> {
    unsafe {
        let a = api::api()?;
        let cns = CString::new(ns).ok()?;
        let cname = CString::new(name).ok()?;
        let k = (a.il2cpp_get_class)(image, cns.as_ptr(), cname.as_ptr());
        if k.is_null() { None } else { Some(k) }
    }
}

fn method_addr(class: *mut api::Il2CppClass, name: &str, argc: i32) -> usize {
    unsafe {
        let Some(a) = api::api() else { return 0 };
        let Ok(cn) = CString::new(name) else { return 0 };
        (a.il2cpp_get_method_addr)(class, cn.as_ptr(), argc) as usize
    }
}

fn install_hook(addr: usize, detour: usize) -> Option<usize> {
    if addr == 0 { return None; }
    unsafe {
        let a = api::api()?;
        let interceptor = api::interceptor();
        if interceptor.is_null() { return None; }
        let t = (a.interceptor_hook)(interceptor, addr as *mut c_void, detour as *mut c_void);
        if t.is_null() { None } else { Some(t as usize) }
    }
}

pub fn install() {
    
    let mut k: *mut api::Il2CppClass = std::ptr::null_mut();
    let candidates: &[(&str, &str, &str)] = &[
        ("umamusume", "Cyan.LocalFile", "DeleteFileHelper"),
        ("umamusume", "Cyan.LocalFile.DeleteFileHelper", ""),
        ("umamusume", "", "Cyan.LocalFile.DeleteFileHelper"),
        ("Assembly-CSharp", "Cyan.LocalFile", "DeleteFileHelper"),
        ("umamusume", "Cyan", "DeleteFileHelper"),
    ];
    for (asm, ns, cn) in candidates {
        let c = api::Symbols::get_class(asm, ns, cn);
        if !c.is_null() {
            api::log_info(&format!(
                "assetcleanupguard: 找到类 via asm={} ns={} cls={}",
                asm, ns, cn
            ));
            k = c;
            break;
        }
    }
    if k.is_null() {
        api::log_warn(
            "assetcleanupguard: DeleteFileHelper 未找到（5 种组合全失败），继续尝试 AssetManager"
        );
    }

    let mut ok = 0;

    
    if !k.is_null() {
        let addr = api::Symbols::get_method_addr(k, "DeleteAllFiles", 0) as usize;
        if let Some(t) = install_hook(addr, delete_all_files as *const () as usize) {
            ORIG_DELETE_ALL.store(t, Ordering::SeqCst);
            ok += 1;
        }

        let addr = api::Symbols::get_method_addr(k, "DeleteFilesByAnyGroupAsync", 3) as usize;
        if let Some(t) = install_hook(addr, delete_by_group as *const () as usize) {
            ORIG_DELETE_GROUP.store(t, Ordering::SeqCst);
            ok += 1;
        }

        let addr = api::Symbols::get_method_addr(k, "DeleteFilesAsync", 2) as usize;
        if let Some(t) = install_hook(addr, delete_files as *const () as usize) {
            ORIG_DELETE_FILES.store(t, Ordering::SeqCst);
            ok += 1;
        }
    }

    
    
    
    let k2 = api::Symbols::get_class("umamusume", "Gallop", "AssetManager");
    if !k2.is_null() {
        {
            let a = api::Symbols::get_method_addr(k2, "DeleteAllAsync", 1) as usize;
            if let Some(t) = install_hook(a, delete_all_async as *const () as usize) {
                ORIG_DELETE_ALL_ASYNC.store(t, Ordering::SeqCst);
                ok += 1;
                api::log_info("assetcleanupguard: hooked AssetManager.DeleteAllAsync");
            }
            let a = api::Symbols::get_method_addr(k2, "DataManagementAsync", 1) as usize;
            if let Some(t) = install_hook(a, data_management_async as *const () as usize) {
                ORIG_DATA_MGMT.store(t, Ordering::SeqCst);
                ok += 1;
                api::log_info("assetcleanupguard: hooked AssetManager.DataManagementAsync");
            }
        }
    } else {
        api::log_warn("assetcleanupguard: AssetManager 未找到");
    }

    api::log_info(&format!("assetcleanupguard: 共挂 {} 个 hook", ok));
}
