mod api;
mod guard;
mod rva_guard;
mod sig_guard;
mod win32_guard;

use std::sync::atomic::{AtomicBool, Ordering};

static BLOCK: AtomicBool = AtomicBool::new(true);

pub fn should_block() -> bool {
    BLOCK.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn hachimi_init_v3(get_api: api::GetApiFn, _version: i32) -> i32 {
    if api::init(get_api).is_none() {
        return api::INIT_ERROR;
    }

    api::log_info("assetcleanupguard: loaded, silent block enabled");

    sig_guard::install();
    rva_guard::install();
    guard::install();
    win32_guard::install();

    let addr = sig_guard::found_addr();
    if addr != 0 {
        api::log_info(&format!(
            "assetcleanupguard: sig hit @ {:#x}, cleanup will be blocked",
            addr
        ));
    } else {
        api::log_warn("assetcleanupguard: sig miss, falling back to win32 layer only");
    }

    api::INIT_OK
}
