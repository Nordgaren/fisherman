#![allow(non_camel_case_types)]

use crate::hook::hook_util::{get_imported_function_index, get_imported_module_index};
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::{addr_of_mut, read_unaligned, write_unaligned};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ImageDirectoryEntryToDataEx, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_READWRITE};
use windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR;

pub struct IATHook {
    pub(crate) module: String,
    pub(crate) function: String,
    pub(crate) hook_address: usize,
    pub(crate) original_address: usize,
}

impl IATHook {
    pub unsafe fn hook(&mut self) -> bool {
        let mut size = 0;
        let base_address = GetModuleHandleA(0 as *const u8) as usize;
        // get Import Table of main module
        let iat_address = ImageDirectoryEntryToDataEx(
            base_address as *const c_void,
            1,
            IMAGE_DIRECTORY_ENTRY_IMPORT,
            addr_of_mut!(size),
            0 as *mut *mut IMAGE_SECTION_HEADER,
        );

        let import_address_table = std::slice::from_raw_parts(
            iat_address as *const IMAGE_IMPORT_DESCRIPTOR,
            size as usize / size_of::<IMAGE_IMPORT_DESCRIPTOR>(),
        );

        // Get and set the original address.
        self.original_address = GetProcAddress(
            GetModuleHandleA(self.module.as_ptr()),
            self.function.as_ptr(),
        )
        .unwrap() as usize;

        // Get the index of the module that contains our function
        let module_indices =
            get_imported_module_index(base_address, import_address_table, self.module.as_bytes());
        if module_indices.is_empty() {
            return false;
        }

        let mut found = false;

        for module_index in module_indices {
            let thunk = (base_address + import_address_table[module_index].FirstThunk as usize)
                as *mut usize;
            // Search through the entire table by name, in case the function is already hooked.
            let function_indices = get_imported_function_index(
                base_address,
                base_address
                    + import_address_table[module_index]
                        .Anonymous
                        .OriginalFirstThunk as usize,
                self.function.as_bytes(),
            );

            if function_indices.is_empty() {
                continue;
            }

            found = true;
            for function_index in function_indices {
                let import_entry_addr = thunk.add(function_index);
                if read_unaligned(import_entry_addr) != self.original_address {
                    // Set the original to this address, in case we want to unhook, later.
                    self.original_address = *import_entry_addr;
                    print!("Previous hook addr: {:X} ", *import_entry_addr)
                }
                let mut protect = 0;
                VirtualProtect(
                    thunk as *const c_void,
                    4096,
                    PAGE_READWRITE,
                    addr_of_mut!(protect),
                );
                write_unaligned(import_entry_addr, self.hook_address);
                VirtualProtect(thunk as *const c_void, 4096, protect, addr_of_mut!(protect));
            }
        }

        found
    }

    pub unsafe fn unhook(&self) -> bool {
        let mut size = 0;
        let base_address = GetModuleHandleA(0 as *const u8) as usize;
        // get Import Table of main module
        let iat_address = ImageDirectoryEntryToDataEx(
            base_address as *const c_void,
            1,
            IMAGE_DIRECTORY_ENTRY_IMPORT,
            addr_of_mut!(size),
            0 as *mut *mut IMAGE_SECTION_HEADER,
        );

        let import_address_table = std::slice::from_raw_parts(
            iat_address as *const IMAGE_IMPORT_DESCRIPTOR,
            size as usize / size_of::<IMAGE_IMPORT_DESCRIPTOR>(),
        );

        // Get the index of the module that contains our function
        let module_indices =
            get_imported_module_index(base_address, import_address_table, self.module.as_bytes());
        if module_indices.is_empty() {
            return false;
        }

        let mut found = false;
        for module_index in module_indices {
            let thunk = (base_address + import_address_table[module_index].FirstThunk as usize)
                as *mut usize;
            // Search through the entire table by name, in case the function was hooked while our hook
            // was in place.
            let function_indices = get_imported_function_index(
                base_address,
                base_address
                    + import_address_table[module_index]
                        .Anonymous
                        .OriginalFirstThunk as usize,
                self.function.as_bytes(),
            );
            if function_indices.is_empty() {
                continue;
            }

            found = true;

            for function_index in function_indices {
                let import_entry_addr = thunk.add(function_index);
                if read_unaligned(import_entry_addr) != self.hook_address {
                    print!(
                        "Hook was re-hooked! {:?} New hook addr: {:X} ",
                        self.function, *import_entry_addr
                    );
                    return false;
                }
                let mut protect = 0;
                VirtualProtect(
                    thunk as *const c_void,
                    4096,
                    PAGE_READWRITE,
                    addr_of_mut!(protect),
                );
                write_unaligned(import_entry_addr, self.original_address);
                VirtualProtect(thunk as *const c_void, 4096, protect, addr_of_mut!(protect));
            }
        }
        found
    }
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use crate::hook::builder::HookBuilder;
    use crate::hook::Hook;
    use crate::util::GetProcAddressInternal;
    use std::ffi::{c_char, CStr};
    use std::mem;
    use windows_sys::core::PCSTR;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    pub unsafe extern "system" fn get_proc_address_hook(
        module_handle: usize,
        proc_name: *const u8,
    ) -> usize {
        let c_string = CStr::from_ptr(proc_name as *const c_char);
        println!("[!] GetProcAddress function: {:X?}", c_string);
        //if you keep a static reference to your hook around, you can hook functions called via
        // GetProcAddress, here.
        // if let Some(hook) = &HOOK {
        //     if let Some(addr) = hook.check_proc_addr_hook_bytes(c_string.to_bytes_with_nul()) {
        //         return addr;
        //     }
        // }

        // return back to GetProcAddress
        let getProcAddress: unsafe extern "system" fn(usize, *const u8) -> usize =
            mem::transmute(GetProcAddressInternal(
                GetModuleHandleA(PCSTR::from("kernel32.dll\0".as_ptr())) as usize,
                "GetProcAddress".as_bytes(),
            ));
        getProcAddress(module_handle, proc_name)
    }

    static mut HOOK: Option<Hook> = None;

    #[test]
    fn iat_hook() {
        unsafe {
            println!("==import address table hook test==");
            let original = GetProcAddress(
                GetModuleHandleA("kernel32.dll\0".as_ptr()),
                "GetProcAddress\0".as_ptr(),
            )
            .unwrap();

            let hook = HookBuilder::new()
                .add_iat_hook(
                    "KERNEL32.dll",
                    "GetProcAddress",
                    get_proc_address_hook as usize,
                )
                .build();
            assert_eq!(original as usize, hook.iat_hooks[0].original_address);

            HOOK = Some(hook);
            println!("[?] Calling hooked GetModuleHandleA with 'LoadLibraryA'");
            GetProcAddress(
                GetModuleHandleA("kernel32.dll\0".as_ptr()),
                "LoadLibraryA\0".as_ptr(),
            );

            if let Some(hook) = &mut HOOK {
                hook.unhook();
            }

            println!("[?] Calling original GetModuleHandleA with 'LoadLibraryA'");
            GetProcAddress(
                GetModuleHandleA("kernel32.dll\0".as_ptr()),
                "LoadLibraryA\0".as_ptr(),
            );
            println!("==import address table hook test end==");
            println!();
        }
    }
}
