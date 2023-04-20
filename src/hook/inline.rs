use crate::scanner::signature::FuncAddr;
use minhook_sys::{MH_CreateHook, MH_EnableHook, MH_OK};
use std::ffi::c_void;
use std::mem;
use std::ptr::addr_of;

pub struct InlineHook {
    pub(crate) function_address: usize,
    pub(crate) hook_address: usize,
    pub(crate) return_address: &'static mut usize,
}

impl InlineHook {
    pub fn hook(&mut self) -> bool {
        unsafe {
            if MH_CreateHook(
                self.function_address as *mut c_void,
                self.hook_address as *mut c_void,
                mem::transmute(self.return_address as *mut usize),
            ) != MH_OK {
                return false;
            };

            MH_EnableHook(self.function_address as *mut c_void) == MH_OK
        }
    }
}
