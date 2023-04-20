use crate::scanner::simple_scanner::SimpleScanner;
use std::mem::size_of;
use std::ptr::addr_of;
use std::{mem, slice};
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

pub struct ModuleSignature {
    pub module: usize,
    pub signature: Signature,
}

impl ModuleSignature {
    pub fn from_ida_pattern(pattern: &str, module: usize) -> Result<Self, ()> {
        Ok(ModuleSignature {
            module,
            signature: Signature::from_ida_pattern(pattern).unwrap(),
        })
    }
}

pub struct Signature {
    pub signature: Vec<u8>,
    pub mask: Vec<u8>,
    pub length: usize,
}

impl Signature {
    pub fn from_ida_pattern(pattern: &str) -> Result<Self, ()> {
        let mut signature = Vec::new();
        let mut mask = Vec::new();

        for byte in pattern.split_whitespace() {
            if byte == "?" || byte == "??" {
                let extend = (byte.len() + 1) / 2;
                mask.resize(mask.len() + extend, 0);
                signature.resize(signature.len() + extend, 0);
            } else {
                let extend = (byte.len() + 1) / 2;
                mask.resize(signature.len() + extend, 0xFF);
                match byte.len() {
                    1 | 2 => signature.push(u8::from_str_radix(byte, 16).map_err(|_| {})?),
                    3 | 4 => signature.extend(
                        u16::from_str_radix(byte, 16)
                            .map_err(|_| {})?
                            .to_be_bytes()
                            .into_iter()
                            .skip_while(|b| *b == 0),
                    ),
                    5 | 6 => signature.extend(
                        u32::from_str_radix(byte, 16)
                            .map_err(|_| {})?
                            .to_be_bytes()
                            .into_iter()
                            .skip_while(|b| *b == 0),
                    ),
                    7 | 8 => signature.extend(
                        u64::from_str_radix(byte, 16)
                            .map_err(|_| {})?
                            .to_be_bytes()
                            .into_iter()
                            .skip_while(|b| *b == 0),
                    ),
                    _ => return Err(()),
                }
            }
        }

        if !mask.iter().any(|x| *x != 0) {
            return Err(());
        }

        let length = signature.len();
        Ok(Self {
            signature,
            mask,
            length,
        })
    }
}

pub trait FuncAddr {
    fn get_address(self) -> usize;
}

impl FuncAddr for usize {
    fn get_address(self) -> usize {
        self
    }
}

impl FuncAddr for &str {
    fn get_address(self) -> usize {
        unsafe {
            match Signature::from_ida_pattern(self) {
                Ok(s) => s.get_address(),
                _ => 0,
            }
        }
    }
}

impl FuncAddr for Signature {
    fn get_address(self) -> usize {
        unsafe {
            let module_handle = GetModuleHandleA(0 as *const u8) as usize;
            let module_bytes = get_module_text_section(module_handle);
            SimpleScanner.scan(module_bytes, &self).unwrap_or(0)
        }
    }
}

impl FuncAddr for ModuleSignature {
    fn get_address(self) -> usize {
        unsafe {
            let module_bytes = get_module_text_section(self.module);
            SimpleScanner
                .scan(module_bytes, &self.signature)
                .unwrap_or(0)
        }
    }
}

unsafe fn get_module_text_section<'a>(module_handle: usize) -> &'a [u8] {
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
