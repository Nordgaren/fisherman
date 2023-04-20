use crate::scanner::signature::FuncAddr;
use minhook_sys::{MH_CreateHook, MH_EnableHook};
use std::ffi::c_void;
use std::mem;
use std::ptr::addr_of;

pub struct InlineHook {
    pub function_address: usize,
    pub hook_address: usize,
    pub return_address: &'static mut usize,
}

impl InlineHook {
    pub fn hook(&mut self) -> bool {
        unsafe {
            let mut return_address = 0 as *mut c_void;
            MH_CreateHook(
                self.function_address as *mut c_void,
                self.hook_address as *mut c_void,
                &mut return_address,
            );
            *(self.return_address as *mut usize) = return_address as usize;

            MH_EnableHook(self.function_address as *mut c_void);
        }
        true
    }
}
