use crate::scanner::signature::{ModuleSignature, Signature};
use crate::scanner::simple_scanner::SimpleScanner;
use crate::util::get_module_slice;
use std::ffi::c_void;
use std::fmt::Debug;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use crate::hook::func_info::FuncInfo;

pub trait FindFunc: Debug {
    fn get_func_info(self) -> Result<FuncInfo, ()>;
}

impl FindFunc for usize {
    fn get_func_info(self) -> Result<FuncInfo, ()> {
        Ok(FuncInfo {
            module: 0 as *mut c_void,
            function_address: self as *mut c_void,
            signature: None,
        })
    }
}

impl FindFunc for &str {
    fn get_func_info(self) -> Result<FuncInfo, ()> {
        Ok(FuncInfo {
            module: 0 as *mut c_void,
            function_address: 0 as *mut c_void,
            signature: match Signature::from_ida_pattern(self) {
                Ok(s) => Some(s),
                Err(_) => return Err(()),
            },
        })
    }
}

impl FindFunc for Signature {
    fn get_func_info(self) -> Result<FuncInfo, ()>{
        Ok(FuncInfo {
            module: 0 as *mut c_void,
            function_address: 0 as *mut c_void,
            signature: Some(self),
        })
    }
}
