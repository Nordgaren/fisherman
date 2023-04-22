use std::ffi::c_void;
use crate::scanner::signature::{ModuleSignature, Signature};
use crate::scanner::simple_scanner::SimpleScanner;
use crate::util::get_module_slice;
use std::fmt::Debug;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

pub trait FuncAddr: Debug {
    fn get_address(&mut self) -> Option<*mut c_void>;
}

impl FuncAddr for usize {
    fn get_address(&mut self) -> Option<*mut c_void> {
        Some(*self as *mut c_void)
    }
}

impl FuncAddr for &str {
    fn get_address(&mut self) -> Option<*mut c_void> {
        match Signature::from_ida_pattern(self) {
            Ok(mut s) => s.get_address(),
            _ => None,
        }
    }
}

impl FuncAddr for Signature {
    fn get_address(&mut self) -> Option<*mut c_void> {
        if self.address.is_some() {
            self.address
        } else {
            unsafe {
                let module_handle = GetModuleHandleA(0 as *const u8) as usize;
                let module_bytes = get_module_slice(module_handle);
                self.address = SimpleScanner.scan(module_bytes, &self);
                self.address
            }
        }
    }
}

impl FuncAddr for ModuleSignature {
    fn get_address(&mut self) -> Option<*mut c_void> {
        if self.signature.address.is_some() {
            self.signature.address
        } else {
            unsafe {
                let module_bytes = get_module_slice(self.module);
                self.signature.address = SimpleScanner.scan(module_bytes, &self.signature);
                self.signature.address
            }
        }
    }
}
