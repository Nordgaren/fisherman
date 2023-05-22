use crate::hook::func_info::FuncInfo;
use minhook_sys::{MH_CreateHook, MH_DisableHook, MH_EnableHook, MH_ERROR_ALREADY_CREATED, MH_OK};
use std::ffi::c_void;
use std::mem;

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
        println!("[!] Original Function! 0x{:X}", arg);
    }

    extern "C" fn hook_func(arg: usize) {
        println!("[!] Hooked function! 0x{:X}", arg * 2);
        unsafe {
            OG_SOME_FUNC(arg / 2);
        }
    }

    static mut OG_SOME_FUNC: extern "C" fn(usize) = hook_func;
    const TEST_VALUE: usize = 0x20;
    #[test]
    fn inline_hook() {
        unsafe {
            println!("==inline hook test==");
            let mut hook = HookBuilder::new()
                .add_inline_hook(
                    some_func as usize,
                    hook_func as usize,
                    &mut OG_SOME_FUNC,
                    None,
                )
                .build();
            println!("[?] calling modified function with 0x{:X}. New function value should be doubled. Original function value should be halved.", TEST_VALUE);
            some_func(TEST_VALUE);
            hook.unhook();
            println!("[?] calling original function, should be original value");
            some_func(TEST_VALUE);
            println!("==inline hook test end==");
            println!();
        }
    }
}
