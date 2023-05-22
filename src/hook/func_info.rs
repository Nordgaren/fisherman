use crate::scanner::signature::Signature;
use std::ffi::c_void;

pub struct FuncInfo {
    pub module: *mut c_void,
    pub function_address: *mut c_void,
    pub signature: Option<Signature>,
}
