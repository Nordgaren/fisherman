#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused)]

use std::mem::size_of;
use std::ptr::addr_of;
use std::{mem, slice};
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, MAX_PATH};
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_EXPORT;
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};

#[cfg(target_arch = "x86_64")]
type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;
#[cfg(target_arch = "x86")]
type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS32;

pub unsafe fn GetProcAddressInternal(base_address: usize, proc_name: &[u8]) -> usize {
    let dos_header: &'static IMAGE_DOS_HEADER = mem::transmute(base_address);
    let nt_headers: &'static IMAGE_NT_HEADERS =
        mem::transmute(base_address + dos_header.e_lfanew as usize);
    let optional_header = &nt_headers.OptionalHeader;
    let export_data_directory =
        &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
    let export_directory: &'static IMAGE_EXPORT_DIRECTORY =
        mem::transmute(base_address + export_data_directory.VirtualAddress as usize);

    let eat_address = base_address + export_directory.AddressOfFunctions as usize;
    let eat_array = core::slice::from_raw_parts(
        eat_address as *const u32,
        export_directory.NumberOfFunctions as usize,
    );

    let mut proc_address = 0;
    let ordinal_test = proc_name.as_ptr() as *const u32;
    if proc_name.len() >= 4 && *ordinal_test >> 16 == 0 {
        let ordinal = *ordinal_test;
        let base = export_directory.Base;

        if (ordinal < base) || (ordinal >= base + export_directory.NumberOfFunctions) {
            return 0;
        }

        proc_address = base_address + eat_array[(ordinal - base) as usize] as usize;
    } else {
        let name_table_address = base_address + export_directory.AddressOfNames as usize;
        let name_table = core::slice::from_raw_parts(
            name_table_address as *const u32,
            export_directory.NumberOfNames as usize,
        );

        for i in 0..export_directory.NumberOfNames as usize {
            let string_address = base_address + name_table[i] as usize;
            let name = core::slice::from_raw_parts(
                string_address as *const u8,
                strlen(string_address as *const u8),
            );

            if name == proc_name {
                let hints_table_address =
                    base_address + export_directory.AddressOfNameOrdinals as usize;
                let hints_table = core::slice::from_raw_parts(
                    hints_table_address as *const u16,
                    export_directory.NumberOfNames as usize,
                );

                proc_address = base_address + eat_array[hints_table[i] as usize] as usize;
            }
        }
    }

    if proc_address >= addr_of!(*export_directory) as usize
        && proc_address < addr_of!(*export_directory) as usize + export_data_directory.Size as usize
    {
        let mut forward_dll = String::from_utf8(
            core::slice::from_raw_parts(
                proc_address as *const u8,
                strlen(proc_address as *const u8),
            )
            .to_vec(),
        )
        .unwrap();

        let split_pos = match forward_dll.find('.') {
            Some(pos) => pos,
            _ => return 0,
        };
        forward_dll = forward_dll.replace(".", "\0");

        let forward_handle = LoadLibraryA(forward_dll.as_ptr()) as usize;
        if forward_handle == 0 {
            return 0;
        }

        let string_address = (proc_address + split_pos + 1) as *const u8;
        let forward_function = core::slice::from_raw_parts(string_address, strlen(string_address));
        proc_address = GetProcAddressInternal(forward_handle, forward_function)
    }

    proc_address
}
#[inline(always)]
pub fn enforce_null_terminated_character(string: &mut String) {
    if !string.ends_with('\0') {
        string.push('\0');
    }
}

// Need internal function for this in unmapped PE state.
pub(crate) unsafe fn strlen(s: *const u8) -> usize {
    let mut len = 0;
    while *s.add(len) != 0 && len <= MAX_PATH as usize {
        len += 1;
    }

    len
}

#[inline(always)]
pub(crate) unsafe fn strlen_with_null(s: *const u8) -> usize {
    strlen(s) + 1
}

// Need internal function for this in unmapped PE state.
pub(crate) unsafe fn strlenw(s: *const u16) -> usize {
    let mut len = 0;
    while *s.add(len) != 0 && len <= MAX_PATH as usize {
        len += 1;
    }

    len
}

#[inline(always)]
pub(crate) unsafe fn strlenw_with_null(s: *const u16) -> usize {
    strlenw(s) + 1
}

// Because you can't use the normal rust copy function in an unmapped PE, for some reason.
pub(crate) unsafe fn copy_buffer<T>(src: *const T, dst: *mut T, len: usize) {
    let total_size = size_of::<T>() * len;
    let src_slice = slice::from_raw_parts(src as *const u8, total_size);
    let dst_slice = slice::from_raw_parts_mut(dst as *mut u8, total_size);

    for i in 0..total_size {
        dst_slice[i] = src_slice[i];
    }
}

pub(crate) unsafe fn zero_memory<T>(buffer: *mut T, len: usize) {
    let total_size = size_of::<T>() * len;
    let dst_slice = slice::from_raw_parts_mut(buffer as *mut u8, total_size);

    for i in 0..total_size {
        dst_slice[i] = 0;
    }
}

pub unsafe fn get_module_slice<'a>(module_handle: usize) -> &'a [u8] {
    let dos_header: &IMAGE_DOS_HEADER = mem::transmute(module_handle);
    let nt_header_address = module_handle + dos_header.e_lfanew as usize;
    let machine = (nt_header_address + 4) as *const u16;
    if *machine == 0x8664 {
        let nt_headers: &IMAGE_NT_HEADERS32 = mem::transmute(nt_header_address);
        slice::from_raw_parts(
            module_handle as *const u8,
            nt_headers.OptionalHeader.SizeOfImage as usize,
        )
    } else if *machine == 0x14C {
        let nt_headers: &IMAGE_NT_HEADERS32 = mem::transmute(nt_header_address);
        slice::from_raw_parts(
            module_handle as *const u8,
            nt_headers.OptionalHeader.SizeOfImage as usize,
        )
    } else {
        slice::from_raw_parts(module_handle as *const u8, 0)
    }
}

pub(crate) unsafe fn get_process_id(procname: &[u8]) -> u32 {
    let hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if INVALID_HANDLE_VALUE == hProcSnap {
        return 0;
    }

    let mut pe32 = PROCESSENTRY32 {
        dwSize: size_of::<PROCESSENTRY32>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; MAX_PATH as usize],
    };

    if Process32First(hProcSnap, &mut pe32) == 0 {
        CloseHandle(hProcSnap);
        return 0;
    }

    let mut pid = 0;

    while Process32Next(hProcSnap, &mut pe32) != 0 {
        if &pe32.szExeFile[..procname.len()] == procname {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);

    pid
}

pub unsafe fn get_relative_pointer<T>(addr: isize, offset: isize, size: isize) -> *const T {
    let offset = (addr + offset) as *const i32;
    let ptr = addr + offset.read_unaligned() as isize + size;
    ptr as *const T
}
