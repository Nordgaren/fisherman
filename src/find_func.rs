use crate::hook::func_info::FuncInfo;
use crate::scanner::signature::Signature;
use std::ffi::c_void;
use std::fmt::Debug;
use windows_sys::core::PCSTR;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

pub trait FindFunc: Debug {
    fn get_func_info(self, module_address: Option<usize>) -> Result<FuncInfo, ()>;
}

impl FindFunc for usize {
    fn get_func_info(self, module_address: Option<usize>) -> Result<FuncInfo, ()> {
        Ok(FuncInfo {
            module: get_module_address(module_address),
            function_address: self as *mut c_void,
            signature: None,
        })
    }
}

impl FindFunc for &str {
    fn get_func_info(self, module_address: Option<usize>) -> Result<FuncInfo, ()> {
        Ok(FuncInfo {
            module: get_module_address(module_address),
            function_address: 0 as *mut c_void,
            signature: match Signature::from_ida_pattern(self) {
                Ok(s) => Some(s),
                Err(_) => return Err(()),
            },
        })
    }
}

impl FindFunc for Signature {
    fn get_func_info(self, module_address: Option<usize>) -> Result<FuncInfo, ()> {
        Ok(FuncInfo {
            module: get_module_address(module_address),
            function_address: 0 as *mut c_void,
            signature: Some(self),
        })
    }
}

#[inline(always)]
fn get_module_address(module_address: Option<usize>) -> *mut c_void {
    if let Some(address) = module_address {
        address as *mut c_void
    } else {
        unsafe { GetModuleHandleA(0 as PCSTR) as *mut c_void }
    }
}
