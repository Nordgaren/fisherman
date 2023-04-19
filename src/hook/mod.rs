use crate::hook::iat::IATHook;
use std::collections::HashMap;
use crate::hook::eat::EATHook;
use crate::hook::inline::InlineHook;

pub mod builder;
mod iat;
mod hook_util;
mod eat;
mod inline;

pub struct Hook {
    eat_hooks: Vec<EATHook>,
    iat_hooks: Vec<IATHook>,
    inline_hooks: Vec<InlineHook>,
    proc_addr_hooks: HashMap<&'static [u8], usize>,
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
