use crate::util::strlen_with_null;
use std::ptr::{addr_of, read_unaligned};
use windows_sys::Win32::System::SystemServices::{IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR};

pub(super) unsafe fn get_imported_function_index(
    base_address: usize,
    original_thunk: usize,
    function_name: &[u8],
) -> Vec<usize> {
    let mut indicies = vec![];
    let mut thunk = original_thunk as *const usize;
    let mut i = 0;
    while thunk.read_unaligned() != 0 {
        let import: &IMAGE_IMPORT_BY_NAME =
            std::mem::transmute(base_address + read_unaligned(thunk));
        let name = std::slice::from_raw_parts(
            addr_of!(import.Name) as *const u8,
            strlen_with_null(addr_of!(import.Name) as *const u8),
        );
        if case_insensitive_compare_strs_as_bytes(name, function_name) {
            indicies.push(i);
        }

        thunk = thunk.add(1);
        i += 1;
    }

    indicies
}

pub(super) unsafe fn get_imported_module_index(
    base_address: usize,
    import_address_table: &[IMAGE_IMPORT_DESCRIPTOR],
    module_name: &[u8],
) -> Vec<usize> {
    let mut indicies = vec![];

    for (i, entry) in import_address_table.iter().enumerate() {
        let string_address = base_address + entry.Name as usize;
        let name = std::slice::from_raw_parts(
            string_address as *const u8,
            strlen_with_null(string_address as *const u8),
        );

        if case_insensitive_compare_strs_as_bytes(name, module_name) {
            indicies.push(i);
        }
    }

    indicies
}

const CASE_BIT: u8 = 0x20;

pub fn case_insensitive_compare_strs_as_bytes(
    string_bytes: &[u8],
    other_string_bytes: &[u8],
) -> bool {
    if string_bytes.len() != other_string_bytes.len() {
        return false;
    }

    for i in 0..string_bytes.len() {
        let mut val = string_bytes[i];
        let mut val2 = other_string_bytes[i];

        if val >= 0x41 && val <= 0x5A {
            val ^= CASE_BIT
        }
        if val2 >= 0x41 && val2 <= 0x5A {
            val2 ^= CASE_BIT
        }

        if val != val2 {
            return false;
        }
    }

    true
}
