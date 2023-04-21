use crate::func_addr::FuncAddr;
use crate::hook::eat::EATHook;
use crate::hook::iat::IATHook;
use crate::hook::inline::InlineHook;
use crate::hook::Hook;
use crate::util::enforce_null_terminated_character;
use minhook_sys::MH_Initialize;
use std::mem;

pub struct HookBuilder {
    hook: Hook,
}

impl HookBuilder {
    pub fn new() -> Self {
        HookBuilder {
            hook: Hook {
                eat_hooks: vec![],
                iat_hooks: vec![],
                inline_hooks: vec![],
                proc_addr_hooks: Default::default(),
            },
        }
    }
    pub fn add_iat_hook(mut self, module: &str, function: &str, hook_address: usize) -> Self {
        let mut module = module.to_owned();
        enforce_null_terminated_character(&mut module);
        let mut function = function.to_owned();
        enforce_null_terminated_character(&mut function);
        self.hook.iat_hooks.push(IATHook {
            module,
            function,
            hook_address,
            original_address: 0,
        });

        self
    }
    pub fn add_eat_hook(mut self, module: &str, function: &str, forward_string: &str) -> Self {
        let mut module = module.to_owned();
        enforce_null_terminated_character(&mut module);
        let mut function = function.to_owned();
        enforce_null_terminated_character(&mut function);
        let mut forward_string = forward_string.to_owned();
        enforce_null_terminated_character(&mut forward_string);
        self.hook.eat_hooks.push(EATHook {
            module,
            function,
            forward_string,
            original_rva: 0,
        });

        self
    }
    pub fn add_inline_hook<T>(
        mut self,
        function_address: impl FuncAddr + 'static,
        hook_address: usize,
        return_address: &mut T,
    ) -> Self {
        unsafe {
            self.hook.inline_hooks.push(InlineHook {
                func_addr_obj: Box::new(function_address),
                function_address: None,
                hook_address,
                return_address: mem::transmute(return_address),
            });
        }

        self
    }
    pub fn add_proc_addr_hook(mut self, function: &str, hook_address: usize) -> Self {
        let mut function = function.to_string();
        enforce_null_terminated_character(&mut function);
        self.hook.proc_addr_hooks.insert(function, hook_address);

        self
    }
    pub unsafe fn build(mut self) -> Hook {
        self.hook.hook();

        self.hook
    }
}
