use crate::hook::Hook;
use crate::hook::iat::IATHook;

pub struct HookBuilder {
    hook: Hook,
}

impl HookBuilder {
    pub fn new() -> Self {
        HookBuilder { hook: Hook { iat_hooks: vec![], proc_addr_hooks: Default::default() } }
    }
    pub fn add_iat_hook(mut self, module: &'static str, function: &'static str, hook_address: usize) -> Self {
        self.hook.iat_hooks.push(IATHook { module, function, hook_address, original_address: 0 });
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