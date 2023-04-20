#![allow(non_camel_case_types)]

use crate::hook::hook_util::{get_imported_function_index, get_imported_module_index};
use std::ffi::{c_char, c_void, CStr};
use std::mem::size_of;
use std::ptr::addr_of_mut;
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

        // Get the index of the module that contains our function
        let module_index =
            get_imported_module_index(base_address, import_address_table, self.module.as_bytes());
        if module_index == usize::MAX {
            return false;
        }

        // Get and set the original address.
        self.original_address = GetProcAddress(
            GetModuleHandleA(self.module.as_ptr()),
            self.function.as_ptr(),
        )
        .unwrap() as usize;

        // Search through the entire table by name, in case the function is already hooked.
        let thunk =
            (base_address + import_address_table[module_index].FirstThunk as usize) as *mut usize;
        let function_index = get_imported_function_index(
            base_address,
            base_address
                + import_address_table[module_index]
                    .Anonymous
                    .OriginalFirstThunk as usize,
            self.function.as_bytes(),
        );
        if function_index != usize::MAX {
            let import_entry_addr = thunk.add(function_index);
            if *import_entry_addr != self.original_address {
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
            *import_entry_addr = self.hook_address;
            VirtualProtect(thunk as *const c_void, 4096, protect, addr_of_mut!(protect));
            return true;
        }

        false
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
        let module_index =
            get_imported_module_index(base_address, import_address_table, self.module.as_bytes());
        if module_index == usize::MAX {
            return false;
        }

        // Search through the entire table by name, in case the function was hooked while .
        let thunk =
            (base_address + import_address_table[module_index].FirstThunk as usize) as *mut usize;
        let function_index = get_imported_function_index(
            base_address,
            base_address
                + import_address_table[module_index]
                    .Anonymous
                    .OriginalFirstThunk as usize,
            self.function.as_bytes(),
        );
        if function_index != usize::MAX {
            let c_string = CStr::from_ptr(self.function.as_ptr() as *const c_char);
            let import_entry_addr = thunk.add(function_index);
            if *import_entry_addr != self.original_address {
                print!(
                    "Hook was re-hooked! {:?} New hook addr: {:X} ",
                    c_string, *import_entry_addr
                );
                return true;
            }
            let mut protect = 0;
            VirtualProtect(
                thunk as *const c_void,
                4096,
                PAGE_READWRITE,
                addr_of_mut!(protect),
            );
            *import_entry_addr = self.original_address;
            VirtualProtect(thunk as *const c_void, 4096, protect, addr_of_mut!(protect));
            return true;
        }

        false
    }
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use std::ffi::{c_char, CStr};
    use std::mem;
    use windows_sys::core::PCSTR;
    use windows_sys::Win32::Foundation::{FARPROC, HMODULE};
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use crate::hook::builder::HookBuilder;
    use crate::util::GetProcAddressInternal;

    pub unsafe extern "system" fn get_proc_address_hook(
        module_handle: HMODULE,
        proc_name: PCSTR,
    ) -> FARPROC {
        let c_string = CStr::from_ptr(proc_name as *const c_char);
        println!("[++] GetProcAddress function: {:?}", c_string);
        // if you keep a static reference to your hook around, you can hook functions called via
        // GetProcAddress, here.
        // if let Some(hook) = &HOOK {
        //     if let Some(addr) = hook.get_proc_addr_hook(c_string.to_bytes_with_nul()) {
        //         return *addr;
        //     }
        // }

        // return back to GetProcAddress
        let getProcAddress: unsafe extern "system" fn(HMODULE, PCSTR) -> FARPROC =
            mem::transmute(GetProcAddressInternal(
                GetModuleHandleA(PCSTR::from("kernel32.dll\0".as_ptr())) as usize,
                "GetProcAddress".as_bytes(),
            ));
        getProcAddress(module_handle, proc_name)
    }

    #[test]
    fn iat_hook() {
        unsafe {
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


            assert_eq!(original as usize, hook.iat_hooks[0].original_address)
        }
    }
}