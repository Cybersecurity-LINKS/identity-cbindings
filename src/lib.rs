pub mod wrapper;

use std::ffi::{c_char, CStr, CString};

use identity_iota::credential::Jws;
pub use wrapper::*;

#[repr(C)]
pub struct rvalue_t {
    pub code: u32
}

#[no_mangle]
pub extern "C" fn setup(stronghold_path: *const c_char, password: *const c_char) -> *mut DidOperations {
    let stronghold_path_str = unsafe { CStr::from_ptr(stronghold_path).to_str().unwrap() };
    let password_str = unsafe { CStr::from_ptr(password).to_str().unwrap() };
    let runtime = tokio::runtime::Runtime::new().unwrap();

    match runtime.block_on(DidOperations::setup(stronghold_path_str, password_str)) {
        Ok(did_operations) => Box::into_raw(Box::new(did_operations)),
        Err(_) => std::ptr::null_mut(),
    }
}



#[no_mangle]
pub extern "C" fn create(did_op: &DidOperations) -> rvalue_t {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    match runtime.block_on(DidOperations::create(&did_op)) {
        Ok(_) => rvalue_t{ code: 0 },
        Err(_) => rvalue_t{ code: 1 },

    }
}


#[no_mangle]
pub extern "C" fn update(did_op: &mut DidOperations) -> rvalue_t {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    match runtime.block_on(DidOperations::update(did_op)) {
        Ok(_) => rvalue_t{ code: 0 },
        Err(_) => rvalue_t{ code: 1 },

    }
}


#[no_mangle]
pub extern "C" fn resolve(did_op: &mut DidOperations, did: *const c_char) -> rvalue_t {
    let did = unsafe { CStr::from_ptr(did).to_str().unwrap() };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    match runtime.block_on(DidOperations::resolve(did_op, did)) {
        Ok(_) => rvalue_t{ code: 0 },
        Err(_) => rvalue_t{ code: 1 },

    }
}


#[no_mangle]
pub extern "C" fn deactivate(did_op: &mut DidOperations) -> rvalue_t {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    match runtime.block_on(DidOperations::deactivate(did_op)) {
        Ok(_) => rvalue_t{ code: 0 },
        Err(_) => rvalue_t{ code: 1 },

    }
}

#[no_mangle]
pub extern "C" fn set_did_document(did_op: &mut DidOperations, document: *const c_char, fragment: *const c_char) -> rvalue_t {
    let document = unsafe { CStr::from_ptr(document).to_str().unwrap() };
    let fragment = unsafe { CStr::from_ptr(fragment).to_str().unwrap() };
    
    match DidOperations::set_did_document(did_op, document, fragment) {
        Ok(_) => rvalue_t{ code: 0 },
        Err(_) => rvalue_t{ code: 1 },
    }

}

#[no_mangle]
pub extern "C" fn sign(did_op: &DidOperations, message: *mut u8, message_len: usize) -> *const c_char {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let message = unsafe {
        std::slice::from_raw_parts(message, message_len)
    };

    match runtime.block_on(DidOperations::sign(did_op, message)) {
        Ok(jws) => jws.as_ptr() as *const c_char,
        Err(_) => std::ptr::null(),
    }
}

#[no_mangle]
pub extern "C" fn verify(did_op: &DidOperations, jws: *const c_char) -> rvalue_t {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let jws = unsafe { CStr::from_ptr(jws).to_str().unwrap() };

    match runtime.block_on(DidOperations::verify(did_op, jws)) {
        Ok(_) => rvalue_t{ code: 0 },
        Err(_) => rvalue_t{ code: 1 },
    }
}

#[no_mangle]
pub extern "C" fn vc_create(did_op: &mut DidOperations, name: *const c_char) -> rvalue_t {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let name = unsafe { CStr::from_ptr(name).to_str().unwrap() };

    match runtime.block_on(DidOperations::vc_create(did_op, name)) {
        Ok(_) => rvalue_t{ code: 0 },
        Err(_) => rvalue_t{ code: 1 },
    }
}

#[no_mangle]
pub extern "C" fn vc_verify(did_op: &mut DidOperations, peer_vc: *const c_char) -> rvalue_t {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let peer_vc = unsafe { CStr::from_ptr(peer_vc).to_str().unwrap() };

    match runtime.block_on(DidOperations::vc_create(did_op, peer_vc)) {
        Ok(_) => rvalue_t{ code: 0 },
        Err(_) => rvalue_t{ code: 1 },
    }
}

#[no_mangle]
pub extern "C" fn get_vc(did_op: &DidOperations) -> *const c_char {
    match DidOperations::get_vc(did_op) {
        Ok(vc) => vc.as_ptr() as *const c_char,
        Err(_) => std::ptr::null(),
    }
}

#[no_mangle]
pub extern "C" fn set_vc(did_op: &mut DidOperations, vc: *const c_char) -> rvalue_t {
    let vc = unsafe { CStr::from_ptr(vc).to_str().unwrap() };
    
    match DidOperations::set_vc(did_op, vc) {
        Ok(_) => rvalue_t{ code: 0 },
        Err(_) => rvalue_t{ code: 1 },
    }
}

