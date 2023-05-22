#![allow(non_camel_case_types)]
// HAS NOT BEEN TESTED, YET!

use crate::util::{copy_buffer, strlen, zero_memory};
use std::ffi::c_void;
use std::mem;
use std::ptr::{addr_of, addr_of_mut};
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_EXPORT;
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_READWRITE};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};

#[cfg(target_arch = "x86_64")]
type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;
#[cfg(target_arch = "x86")]
type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS32;

pub struct EATHook {
    pub module_name: String,
    pub(crate) module_address: usize,
    pub function_name: String,
    pub(crate) function_address: usize,
    pub(crate) forward_string: String,
    pub(crate) forward_address: usize,
    pub(crate) original_rva: u32,
    pub(crate) original_export_dir_size: u32,
}

impl EATHook {
    pub unsafe fn hook(&mut self) -> bool {
        let base_address = self.module_address;
        let dos_header: &'static IMAGE_DOS_HEADER = mem::transmute(base_address);
        let nt_headers: &'static mut IMAGE_NT_HEADERS =
            mem::transmute(base_address + dos_header.e_lfanew as usize);
        let optional_header = &mut nt_headers.OptionalHeader;
        let mut export_data_directory =
            &mut optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

        if self.original_export_dir_size == 0 {
            self.original_export_dir_size = export_data_directory.Size;
        }

        let export_directory: &'static IMAGE_EXPORT_DIRECTORY =
            mem::transmute(base_address + export_data_directory.VirtualAddress as usize);

        let eat_address = base_address + export_directory.AddressOfFunctions as usize;
        let eat_array = core::slice::from_raw_parts_mut(
            eat_address as *mut u32,
            export_directory.NumberOfFunctions as usize,
        );

        let name_table_address = base_address + export_directory.AddressOfNames as usize;
        let name_table = core::slice::from_raw_parts(
            name_table_address as *const u32,
            export_directory.NumberOfNames as usize,
        );

        for i in 0..export_directory.NumberOfNames as usize {
            let string_address = (base_address + name_table[i] as usize) as *const u8;
            let name = core::slice::from_raw_parts(string_address, strlen(string_address));

            if name == self.function_name.as_bytes() {
                let mut protect = 0;
                VirtualProtect(
                    addr_of!(*export_directory) as *const c_void,
                    export_data_directory.Size as usize,
                    PAGE_READWRITE,
                    addr_of_mut!(protect),
                );

                export_data_directory.Size += self.forward_string.len() as u32;

                let hints_table_address =
                    base_address + export_directory.AddressOfNameOrdinals as usize;
                let hints_table = core::slice::from_raw_parts(
                    hints_table_address as *const u16,
                    export_directory.NumberOfNames as usize,
                );

                let forward_ptr = base_address
                    + export_data_directory.VirtualAddress as usize
                    + export_data_directory.Size as usize;

                self.original_rva = eat_array[hints_table[i] as usize];

                eat_array[hints_table[i] as usize] = (forward_ptr - base_address) as u32;
                copy_buffer(
                    self.forward_string.as_ptr(),
                    forward_ptr as *mut u8,
                    self.forward_string.len(),
                );

                VirtualProtect(
                    addr_of!(*export_directory) as *const c_void,
                    export_data_directory.Size as usize,
                    protect,
                    addr_of_mut!(protect),
                );

                return true;
            }
        }

        false
    }

    pub unsafe fn unhook(&mut self) -> bool {
        let base_address = GetModuleHandleA(self.module_name.as_ptr()) as usize;
        let dos_header: &'static IMAGE_DOS_HEADER = mem::transmute(base_address);
        let nt_headers: &'static mut IMAGE_NT_HEADERS =
            mem::transmute(base_address + dos_header.e_lfanew as usize);
        let optional_header = &mut nt_headers.OptionalHeader;
        let mut export_data_directory =
            &mut optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        let export_directory: &'static IMAGE_EXPORT_DIRECTORY =
            mem::transmute(base_address + export_data_directory.VirtualAddress as usize);

        let eat_address = base_address + export_directory.AddressOfFunctions as usize;
        let eat_array = core::slice::from_raw_parts_mut(
            eat_address as *mut u32,
            export_directory.NumberOfFunctions as usize,
        );

        let name_table_address = base_address + export_directory.AddressOfNames as usize;
        let name_table = core::slice::from_raw_parts(
            name_table_address as *const u32,
            export_directory.NumberOfNames as usize,
        );

        for i in 0..export_directory.NumberOfNames as usize {
            let string_address = (base_address + name_table[i] as usize) as *const u8;
            let name = core::slice::from_raw_parts(string_address, strlen(string_address));

            if name == self.function_name.as_bytes() {
                let mut protect = 0;
                VirtualProtect(
                    addr_of!(*export_directory) as *const c_void,
                    export_data_directory.Size as usize,
                    PAGE_READWRITE,
                    addr_of_mut!(protect),
                );

                export_data_directory.Size -= self.forward_string.len() as u32;

                let hints_table_address =
                    base_address + export_directory.AddressOfNameOrdinals as usize;
                let hints_table = core::slice::from_raw_parts(
                    hints_table_address as *const u16,
                    export_directory.NumberOfNames as usize,
                );

                let forward_ptr = base_address
                    + export_data_directory.VirtualAddress as usize
                    + export_data_directory.Size as usize;

                let mut protect = 0;
                eat_array[hints_table[i] as usize] = self.original_rva;
                zero_memory(forward_ptr as *mut u8, self.forward_string.len());

                VirtualProtect(
                    addr_of!(*export_directory) as *const c_void,
                    export_data_directory.Size as usize,
                    protect,
                    addr_of_mut!(protect),
                );

                return true;
            }
        }

        false
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::hook::builder::HookBuilder;
//     use std::collections::HashMap;
//
//     #[test]
//     fn eat_hook() {
//
//     }
// }
