pub mod wrapper;

use std::ffi::{c_char, CStr, CString};

use identity_iota::credential::Jws;
pub use wrapper::*;

#[repr(C)]
pub struct rvalue_t {
    pub code: u32
}

/* WALLET */

#[no_mangle]
pub extern "C" fn setup(stronghold_path: *const c_char, password: *const c_char) -> *mut Wallet {
    let stronghold_path_str = unsafe { CStr::from_ptr(stronghold_path).to_str().unwrap() };
    let password_str = unsafe { CStr::from_ptr(password).to_str().unwrap() };
    let runtime = tokio::runtime::Runtime::new().unwrap();

    match runtime.block_on(Wallet::setup(stronghold_path_str, password_str)) {
        Ok(w) => Box::into_raw(Box::new(w)),
        Err(_) => std::ptr::null_mut(),
    }
}

/* DID FUNCTIONS */

#[no_mangle]
pub extern "C" fn did_create(wallet: &Wallet) -> *mut Did {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    match runtime.block_on(Did::did_create(wallet)) {
        Ok(did) => Box::into_raw(Box::new(did)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn did_resolve(wallet: &mut Wallet, did: *const c_char) -> *mut Did {
    let did = unsafe { CStr::from_ptr(did).to_str().unwrap() };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    match runtime.block_on(Did::did_resolve(wallet, did)) {
        Ok(did) => Box::into_raw(Box::new(did)),
        Err(_) => std::ptr::null_mut(),
    }
}

/* #[no_mangle]
pub extern "C" fn update(did_op: &mut DidOperations) -> rvalue_t {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    match runtime.block_on(DidOperations::update(did_op)) {
        Ok(_) => rvalue_t{ code: 0 },
        Err(_) => rvalue_t{ code: 1 },

    }
} */


/* #[no_mangle]
pub extern "C" fn deactivate(did_op: &mut DidOperations) -> rvalue_t {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    match runtime.block_on(DidOperations::deactivate(did_op)) {
        Ok(_) => rvalue_t{ code: 0 },
        Err(_) => rvalue_t{ code: 1 },

    }
} */

#[no_mangle]
pub extern "C" fn did_get(did: &Did) -> *const c_char {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    match runtime.block_on(Did::did_get(did)) {
        Ok(did_doc) => {
            let c_string = CString::new(did_doc).expect("CString::new failed");
            c_string.into_raw()},
        Err(_) => std::ptr::null(),
    }
}

//TODO
/// # Safety
/// The ptr should be a valid pointer to the string allocated by rust
/* #[no_mangle]
pub unsafe extern fn free_did(ptr: *const c_char) {
    // Take the ownership back to rust and drop the owner
    let _ = CString::from_raw(ptr as *mut _);
} */

#[no_mangle]
pub extern "C" fn did_set(document: *const c_char, fragment: *const c_char) -> *mut Did {
    let document = unsafe { CStr::from_ptr(document).to_str().unwrap() };
    let fragment = unsafe { CStr::from_ptr(fragment).to_str().unwrap() };
    
    match Did::did_set(document, fragment) {
        Ok(did) => Box::into_raw(Box::new(did)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn did_sign(wallet: &Wallet, did: &Did, message: *mut u8, message_len: usize) -> *const c_char {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let message = unsafe {
        std::slice::from_raw_parts(message, message_len)
    };

    match runtime.block_on(Did::did_sign(did, wallet, message)) {
        Ok(jws) => {
            let c_string = CString::new(jws).expect("CString::new failed");
            c_string.into_raw()},
        Err(_) => std::ptr::null(),
    }
}

#[no_mangle]
pub extern "C" fn did_verify(did: &Did, jws: *const c_char) -> rvalue_t {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let jws = unsafe { CStr::from_ptr(jws).to_str().unwrap() };

    match runtime.block_on(Did::did_verify(did, jws)) {
        Ok(_) => rvalue_t{ code: 0 },
        Err(_) => rvalue_t{ code: 1 },
    }
}

/* VC */

#[no_mangle]
pub extern "C" fn vc_create(wallet: &mut Wallet, did: &Did, name: *const c_char) -> *mut VC {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let name = unsafe { CStr::from_ptr(name).to_str().unwrap() };

    match runtime.block_on(VC::vc_create(wallet, did, name)) {
        Ok(vc) => Box::into_raw(Box::new(vc)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn vc_verify(wallet: &Wallet, peer_vc: *const c_char) -> *mut Did {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let peer_vc = unsafe { CStr::from_ptr(peer_vc).to_str().unwrap() };

    match runtime.block_on(VC::vc_verify(wallet, peer_vc)) {
        Ok(did) => Box::into_raw(Box::new(did)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn vc_get(vc: &VC) -> *const c_char {
    match VC::vc_get(vc) {
        Ok(vc) => {
        let c_vc = CString::new(vc).expect("CString::new failed");
        c_vc.into_raw()},
        Err(_) => std::ptr::null(),
    }
}

#[no_mangle]
pub extern "C" fn vc_set(vc_jwt: *const c_char) -> *mut VC {
    let vc = unsafe { CStr::from_ptr(vc_jwt).to_str().unwrap() };
    
    match VC::vc_set(vc) {
        Ok(vc) => Box::into_raw(Box::new(vc)),
        Err(_) => std::ptr::null_mut(),
    }
}

