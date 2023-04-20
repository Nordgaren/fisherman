use crate::scanner::signature::FuncAddr;
use minhook_sys::{MH_CreateHook, MH_DisableHook, MH_EnableHook, MH_ERROR_ALREADY_CREATED, MH_OK};
use std::ffi::c_void;
use std::mem;
use std::ptr::addr_of;

pub struct InlineHook {
    pub(crate) function_address: usize,
    pub(crate) hook_address: usize,
    pub(crate) return_address: &'static mut usize,
}

impl InlineHook {
    pub fn hook(&self) -> bool {
        unsafe {
            let status = MH_CreateHook(
                self.function_address as *mut c_void,
                self.hook_address as *mut c_void,
                mem::transmute(self.return_address as *mut usize),
            );

            if status != MH_OK && status != MH_ERROR_ALREADY_CREATED {
                return false;
            };

            MH_EnableHook(self.function_address as *mut c_void) == MH_OK
        }
    }
    pub fn unhook(&self) -> bool {
        unsafe { MH_DisableHook(self.function_address as *mut c_void) == MH_OK }
    }
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use crate::hook::builder::HookBuilder;
    use std::ptr::addr_of;

    extern "C" fn some_func(arg: &usize) {
        println!("Original Function! {:X}", arg);
    }

    extern "C" fn hook_func(arg: &usize) {
        println!("Hooked function! {:X}", arg * 2);
        unsafe {
            og_some_func(&(arg / 2));
        }
    }

    struct WorldChrMan;

    static mut og_some_func: extern "C" fn(&usize) = hook_func;

    static mut og_get_char_ins_from_handle: unsafe extern "C" fn(*const WorldChrMan, &usize) =
        get_char_ins_from_handle;

    unsafe extern "C" fn get_char_ins_from_handle(
        worldChrMan: *const WorldChrMan,
        chrInsHandlePtr: &usize,
    ) {
        println!("lol");
        og_get_char_ins_from_handle(worldChrMan, chrInsHandlePtr);
    }

    #[test]
    fn inline_hook() {
        unsafe {
            let mut hook = HookBuilder::new()
                .add_inline_hook(some_func as usize, hook_func as usize, &mut og_some_func)
                .add_inline_hook(
                    "48 83 EC 28 E8 17 FF FF FF 48 85 C0 74 08 48 8B 00 48 83 C4 28 C3",
                    get_char_ins_from_handleas as usize,
                    &mut og_get_char_ins_from_handle,
                )
                .build();
        }
    }
}
