pub mod hook;
mod scanner;
mod util;

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use crate::hook::builder::HookBuilder;
    use crate::scanner::signature::Signature;
    use crate::util::GetProcAddressInternal;
    use std::ffi::{c_char, CStr};
    use std::mem;
    use windows_sys::core::PCSTR;
    use windows_sys::Win32::Foundation::{FARPROC, HMODULE};
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    pub unsafe extern "system" fn get_proc_address_hook(
        module_handle: HMODULE,
        proc_name: PCSTR,
    ) -> FARPROC {
        let c_string = CStr::from_ptr(proc_name as *const c_char);
        println!("[+] GetProcAddress function: {:?}", c_string);
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

    pub unsafe extern "system" fn load_library_a_hook(module_name: PCSTR) -> HMODULE {
        let c_string = CStr::from_ptr(module_name as *const c_char);
        println!("[+] LoadLibraryA module: {:?}", c_string);

        // return back to LoadLibraryA
        let loadLibraryA: fn(PCSTR) -> HMODULE = mem::transmute(GetProcAddress(
            GetModuleHandleA(PCSTR::from("kernel32.dll\0".as_ptr())),
            "LoadLibraryA".as_ptr(),
        ));
        loadLibraryA(module_name)
    }

    #[test]
    fn it_works() {
        unsafe {
            let original = GetProcAddress(
                GetModuleHandleA("kernel32.dll\0".as_ptr()),
                "LoadLibraryA\0".as_ptr(),
            )
            .unwrap();
            let hook = HookBuilder::new()
                .add_iat_hook(
                    "KERNEL32.dll",
                    "GetProcAddress",
                    get_proc_address_hook as usize,
                )
                .build();

            let hooked = GetProcAddress(
                GetModuleHandleA("kernel32.dll\0".as_ptr()),
                "LoadLibraryA\0".as_ptr(),
            )
            .unwrap();

            assert_eq!(original as usize, hooked as usize)
        }
    }

    extern "C" fn some_func(arg: usize) {
        println!("Hurray! {:X}", arg);
    }

    extern "C" fn hook_func(arg: usize) {
        println!("Hooked! {:X}", arg * 2);
        unsafe {
            og_some_func(arg / 2);
        }
    }

    static mut og_some_func: extern "C" fn(usize) = hook_func;

    #[test]
    fn inline_hook() {
        unsafe {
            let mut hook = HookBuilder::new()
                .add_inline_hook(
                    some_func as usize,
                    hook_func as usize,
                    &mut og_some_func,
                )
                .build();

            some_func(0x20);
        }
    }
}
