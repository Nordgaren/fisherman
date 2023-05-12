use crate::find_func::FindFunc;
use minhook_sys::{MH_CreateHook, MH_DisableHook, MH_EnableHook, MH_ERROR_ALREADY_CREATED, MH_OK};
use std::ffi::c_void;
use std::mem;
use crate::hook::func_info::FuncInfo;

pub struct InlineHook {
    pub(crate) func_info: FuncInfo,
    pub(crate) hook_address: usize,
    pub(crate) return_address: &'static mut usize,
}

impl InlineHook {
    pub unsafe fn hook(&mut self) -> bool {
        let function_address = self.func_info.function_address;
        let status = MH_CreateHook(
            function_address,
            self.hook_address as *mut c_void,
            mem::transmute(self.return_address as *mut usize),
        );

        if status != MH_OK && status != MH_ERROR_ALREADY_CREATED {
            return false;
        };

        MH_EnableHook(function_address) == MH_OK
    }
    pub unsafe fn unhook(&mut self) -> bool {
        let function_address = self.func_info.function_address;
        MH_DisableHook(function_address) == MH_OK
    }
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use crate::hook::builder::HookBuilder;

    extern "C" fn some_func(arg: usize) {
        println!("Original Function! {:X}", arg);
    }

    extern "C" fn hook_func(arg: usize) {
        println!("Hooked function! {:X}", arg * 2);
        unsafe {
            og_some_func(arg / 2);
        }
    }
    static mut og_some_func: extern "C" fn(usize) = hook_func;

    #[test]
    fn inline_hook() {
        unsafe {
            let mut hook = HookBuilder::new()
                .add_inline_hook(some_func as usize, hook_func as usize, &mut og_some_func)
                .build();

            some_func(0x20);
            hook.unhook();
            some_func(0x20);
        }
    }
}
