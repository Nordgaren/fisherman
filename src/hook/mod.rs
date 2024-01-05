#![allow(non_camel_case_types)]
#![allow(unused)]

use crate::hook::eat::EATHook;
use crate::hook::iat::IATHook;
use crate::hook::inline::InlineHook;
use crate::scanner::simple_scanner::SimpleScanner;
use crate::util::{enforce_null_terminated_character, get_module_slice, get_process_id};
use minhook_sys::MH_Initialize;
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem;
use windows_sys::core::PCSTR;
use windows_sys::Win32::Foundation::{FALSE, HANDLE};
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;

use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO, SYSTEM_INFO_0};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_ALL_ACCESS};

#[cfg(target_arch = "x86")]
type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS32;

#[cfg(target_arch = "x86_64")]
type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;

pub mod builder;
mod eat;
pub mod func_info;
pub mod hook_util;
pub mod iat;
pub mod inline;

#[derive(Default)]
pub struct Hook {
    pub(crate) eat_hooks: EatHooks,
    pub(crate) iat_hooks: Vec<IATHook>,
    pub(crate) inline_hooks: Vec<InlineHook>,
    pub(crate) proc_addr_hooks: HashMap<String, usize>,
}

#[derive(Default)]
pub(crate) struct EatHooks {
    pub(crate) hooks: Vec<EATHook>,
    pub(crate) forward_string_location: usize,
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
            print!("[+] IAT Hooking function: {}", iat_hook.function);

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
            if let Some(signature) = &mut inline_hook.func_info.signature {
                let module_bytes = get_module_slice(inline_hook.func_info.module as usize);
                if let Some(addr) = SimpleScanner.scan(module_bytes, signature) {
                    inline_hook.func_info.function_address =
                        inline_hook.func_info.module.add(addr as usize)
                } else {
                    print!("[!] Scan failed for signature: {:X?} ", signature);
                    continue;
                }
            }

            print!(
                "[+] Inline Hooking function @ {:X?} ",
                inline_hook.func_info.function_address
            );
            if inline_hook.hook() {
                print!("Hook succeeded!\n");
            } else {
                print!("Hook failed!\n");
            }
        }

        self.process_eat_hooks();

        for eat_hook in &mut self.eat_hooks.hooks {
            print!("[+] EAT Hooking function @ {:?} ", eat_hook.function_name);

            if eat_hook.hook() {
                print!("Hook succeeded!\n");
            } else {
                print!("Hook failed!\n");
            }
        }
    }

    pub unsafe fn unhook(&mut self) {
        for iat_hook in &self.iat_hooks {
            print!("[-] Unhooking IAT hook: {} ", iat_hook.function);

            if iat_hook.unhook() {
                print!("Unhooking succeeded!\n");
            } else {
                print!("Unhook failed!\n");
            }
        }
        for inline_hook in &mut self.inline_hooks {
            print!(
                "[-] Unhooking Inline hook @ {:X} ",
                inline_hook.func_info.function_address as usize
            );

            if inline_hook.unhook() {
                print!("Unhooking succeeded!\n");
            } else {
                print!("Unhook failed!\n");
            }
        }
        for eat_hook in &mut self.eat_hooks.hooks {
            print!("[-] Unhooking EAT hook @ {:?} ", eat_hook.function_name);

            if eat_hook.unhook() {
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
    // This is still very unfinished. I basically need to allocate a new string
    fn process_eat_hooks(&mut self) {
        let mut module_info_hashmap = HashMap::<&str, usize>::default();
        // Get the size of the chunk we need to allocate, which will basically be where we store all the forward strings.
        // I think I also need to add the name of the module we are forwarding to (probably this module, so I can get that
        // from some windows API calls.
        for eat_hook in &mut self.eat_hooks.hooks {
            if let Some(size) = module_info_hashmap.get_mut(eat_hook.module_name.as_str()) {
                *size += eat_hook.function_name.len();
            } else {
                module_info_hashmap
                    .insert(eat_hook.module_name.as_str(), eat_hook.function_name.len());
            }
        }

        // Go over each module and setup the chunks. Tag the chunks with the size, so we have it for slices, and for de-allocation.
        for (string, size_ptr) in module_info_hashmap.iter_mut() {
            unsafe {
                let process;
                let module_name;
                if string.len() == 0 {
                    process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
                    module_name = PCSTR::from(0 as *const u8);
                } else {
                    process = OpenProcess(
                        PROCESS_ALL_ACCESS,
                        FALSE,
                        get_process_id(string.as_bytes()),
                    );
                    module_name = PCSTR::from(string.as_ptr());
                };

                let module_address = GetModuleHandleA(module_name);

                let dos_header: &IMAGE_DOS_HEADER = mem::transmute(module_address as usize);
                let nt_headers: &IMAGE_NT_HEADERS =
                    mem::transmute(module_address as usize + dos_header.e_lfanew as usize);

                let mut system_info = SYSTEM_INFO {
                    Anonymous: SYSTEM_INFO_0 { dwOemId: 0 },
                    dwPageSize: 0,
                    lpMinimumApplicationAddress: 0 as *mut c_void,
                    lpMaximumApplicationAddress: 0 as *mut c_void,
                    dwActiveProcessorMask: 0,
                    dwNumberOfProcessors: 0,
                    dwProcessorType: 0,
                    dwAllocationGranularity: 0,
                    wProcessorLevel: 0,
                    wProcessorRevision: 0,
                };
                GetSystemInfo(&mut system_info);

                let size = *size_ptr + 0x10; // Reserve space for the actual size of the chunk, and keep the start of the address 16 byte aligned.
                let address = VirtualAllocEx(
                    process,
                    (module_address as usize
                        + nt_headers.OptionalHeader.SizeOfImage as usize
                        + system_info.dwAllocationGranularity as usize)
                        as *const c_void,
                    size,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE,
                );
                // Write the size of the chunk to the start of the the chunk.
                *(address as *mut usize) = *size_ptr;
                // Write the start of the chunk address to the usize in the hashmap.
                *size_ptr = address as usize + 0x10;
            }
        }
    }
    pub fn get_original_func_addr_iat(&self, function_name: &str) -> Option<usize> {
        let mut name = function_name.to_string();
        enforce_null_terminated_character(&mut name);
        for hook in &self.iat_hooks {
            if hook.function == name {
                return Some(hook.original_address);
            }
        }

        None
    }
}
