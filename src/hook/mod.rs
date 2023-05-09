use crate::hook::eat::EATHook;
use crate::hook::iat::IATHook;
use crate::hook::inline::InlineHook;
use minhook_sys::MH_Initialize;
use std::collections::HashMap;

pub mod builder;
pub mod eat;
pub mod hook_util;
pub mod iat;
pub mod inline;

#[derive(Default)]
pub struct Hook {
    pub(crate) eat_hooks: Vec<EATHook>,
    pub(crate) iat_hooks: Vec<IATHook>,
    pub(crate) inline_hooks: Vec<InlineHook>,
    pub(crate) proc_addr_hooks: HashMap<String, usize>,
}

impl Hook {
    pub fn new() -> Self {
        Hook {
            eat_hooks: Default::default(),
            iat_hooks: Default::default(),
            inline_hooks: Default::default(),
            proc_addr_hooks: Default::default(),
        }
    }
    pub unsafe fn hook(&mut self) {
        for iat_hook in &mut self.iat_hooks {
            print!("[+] Hooking function: {}", iat_hook.function);

            if iat_hook.hook() {
                print!("Hook succeeded!\n");
            } else {
                print!("Hook failed!\n");
            }
        }
        if !self.inline_hooks.is_empty() {
            MH_Initialize();
        }

        for inline_hook in &mut self.inline_hooks {
            print!("[+] Hooking function @ {:X?} ", inline_hook.func_addr_obj);
            inline_hook.get_function_addr();

            if inline_hook.hook() {
                print!("Hook succeeded!\n");
            } else {
                print!("Hook failed!\n");
            }
        }
    }

    pub unsafe fn unhook(&mut self) {
        for iat_hook in &self.iat_hooks {
            print!("[-] Unhooking function: {} ", iat_hook.function);

            if iat_hook.unhook() {
                print!("Unhooking succeeded!\n");
            } else {
                print!("Unhook failed!\n");
            }
        }
        for inline_hook in &mut self.inline_hooks {
            print!("[-] Unhooking function @ {:X?} ", inline_hook.func_addr_obj);

            if inline_hook.unhook() {
                print!("Unhooking succeeded!\n");
            } else {
                print!("Unhook failed!\n");
            }
        }
    }

    pub fn check_proc_addr_hook(&self, key: &str) -> Option<usize> {
        self.proc_addr_hooks.get(key).cloned()
    }
    pub fn check_proc_addr_hook_bytes(&self, key: &[u8]) -> Option<usize> {
        let str = match std::str::from_utf8(key) {
            Ok(str) => str,
            _ => {
                return None;
            }
        };
        self.proc_addr_hooks.get(str).cloned()
    }
}
