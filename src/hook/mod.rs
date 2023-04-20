use crate::hook::eat::EATHook;
use crate::hook::iat::IATHook;
use crate::hook::inline::InlineHook;
use std::collections::HashMap;

pub mod builder;
pub mod eat;
pub mod hook_util;
pub mod iat;
pub mod inline;

pub struct Hook {
    pub eat_hooks: Vec<EATHook>,
    pub iat_hooks: Vec<IATHook>,
    pub inline_hooks: Vec<InlineHook>,
    pub proc_addr_hooks: HashMap<&'static [u8], usize>,
}

impl Hook {
    pub fn hook(&mut self) {
        for iat_hook in &mut self.iat_hooks {
            print!("Hooking: {}", iat_hook.function);

            if unsafe { iat_hook.hook() } {
                print!("Hook succeeded!\n");
            } else {
                print!("Hook failed!\n");
            }
        }
        for inline_hooks in &mut self.inline_hooks {
            print!("Hooking function at: {:X}", inline_hooks.function_address);

            if unsafe { inline_hooks.hook() } {
                print!("Hook succeeded!\n");
            } else {
                print!("Hook failed!\n");
            }
        }
    }

    pub fn unhook(&self) {
        for iat_hook in &self.iat_hooks {
            print!("Unhooking: {} ", iat_hook.function);

            if unsafe { iat_hook.unhook() } {
                print!("Unhooking succeeded!\n");
            } else {
                print!("Unhook failed!\n");
            }
        }
    }

    pub fn get_proc_addr_hook(&self, key: &[u8]) -> Option<&usize> {
        self.proc_addr_hooks.get(key)
    }
}
