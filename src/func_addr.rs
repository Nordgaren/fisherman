use std::fmt::Debug;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use crate::scanner::signature::{ModuleSignature, Signature};
use crate::scanner::simple_scanner::SimpleScanner;
use crate::util::get_module_text_section;

pub trait FuncAddr: Debug {
    fn get_address(&mut self) -> usize;
}

impl FuncAddr for usize {
    fn get_address(&mut self) -> usize {
        *self
    }
}

impl FuncAddr for &str {
    fn get_address(&mut self) -> usize {
        match Signature::from_ida_pattern(self) {
            Ok(mut s) => s.get_address(),
            _ => 0,
        }
    }
}

impl FuncAddr for Signature {
    fn get_address(&mut self) -> usize {
        if let Some(addr) = self.address {
            addr
        } else {
            unsafe {
                let module_handle = GetModuleHandleA(0 as *const u8) as usize;
                let module_bytes = get_module_text_section(module_handle);
                self.address = SimpleScanner.scan(module_bytes, &self);
                self.address.unwrap_or_default()
            }
        }
    }
}

impl FuncAddr for ModuleSignature {
    fn get_address(&mut self) -> usize {
        if let Some(addr) = self.signature.address {
            addr
        } else {
            unsafe {
                let module_bytes = get_module_text_section(self.module);
                self.signature.address = SimpleScanner
                    .scan(module_bytes, &self.signature);
                self.signature.address.unwrap_or_default()
            }
        }
    }
}