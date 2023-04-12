use std::ptr::addr_of;
use windows_sys::Win32::System::SystemServices::{IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR};
use crate::util::strlen;

pub(super) unsafe fn get_imported_function_index(base_address: usize, original_thunk: usize, function_name: &[u8]) -> usize {
    let mut thunk = original_thunk as *const usize;
    let mut index = 0;
    while *thunk != 0 {
        let import: &IMAGE_IMPORT_BY_NAME = std::mem::transmute(base_address + *thunk);
        let name = std::slice::from_raw_parts(addr_of!(import.Name) as *const u8, strlen(addr_of!(import.Name) as * const u8) + 1);
        if name == function_name {
            return index;
        }

        thunk = thunk.add(1);
        index += 1;
    }

    usize::MAX
}

pub(super) unsafe fn get_imported_module_index(base_address: usize, import_address_table: &[IMAGE_IMPORT_DESCRIPTOR], module_name: &[u8]) -> usize {
    for (i , entry) in import_address_table.iter().enumerate() {
        let string_address = base_address + entry.Name as usize;
        let name = std::slice::from_raw_parts(string_address as *const u8, strlen(string_address as *const u8) + 1);
        if name == module_name {
            return i;
        }
    }

    usize::MAX
}