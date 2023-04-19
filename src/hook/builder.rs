use crate::hook::eat::EATHook;
use crate::hook::Hook;
use crate::hook::iat::IATHook;
use crate::hook::inline::InlineHook;
use crate::scanner::signature::FuncAddr;
use crate::util::enforce_null_terminated_character;

pub struct HookBuilder {
    hook: Hook,
}

impl HookBuilder {
    pub fn new() -> Self {
        HookBuilder { hook: Hook { eat_hooks: vec![], iat_hooks: vec![], inline_hooks: vec![], proc_addr_hooks: Default::default() } }
    }
    pub fn add_iat_hook(mut self, module: &str, function: &str, hook_address: usize) -> Self {
        let mut module = module.to_owned();
        enforce_null_terminated_character(&mut module);
        let mut function = function.to_owned();
        enforce_null_terminated_character(&mut function);
        self.hook.iat_hooks.push(IATHook { module, function, hook_address, original_address: 0 });

        self
    }
    pub fn add_eat_hook(mut self, module: &str, function: &str, forward_string: &'static str) -> Self {
        let mut module = module.to_owned();
        enforce_null_terminated_character(&mut module);
        let mut function = function.to_owned();
        enforce_null_terminated_character(&mut function);
        let mut forward_string = forward_string.to_owned();
        enforce_null_terminated_character(&mut forward_string);
        self.hook.eat_hooks.push(EATHook { module, function, forward_string, original_rva: 0 });

        self
    }
    pub fn add_inline_hook(mut self, module: &str, function_address: impl FuncAddr + 'static, hook_address: usize) -> Self {
        let mut module = module.to_owned();
        enforce_null_terminated_character(&mut module);
        self.hook.inline_hooks.push(InlineHook { module, function_address: Box::new(function_address), hook_address, return_address: 0 });

        self
    }
    pub fn add_proc_addr_hook(mut self, function: &'static str, hook_address: usize) -> Self {
        self.hook.proc_addr_hooks.insert(function.as_bytes(), hook_address);

        self
    }
    pub fn build(mut self) -> Hook {
        self.hook.hook();

        self.hook
    }
}

