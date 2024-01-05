# Fisherman
a hooking library aimed to allow the user to choose from multiple hook types.  

***This project is in very early development, and the API may change majorly between updates!***
## How to use

### Inline Hook
Inline hook takes a usize, IDA/AoB string, Signature or ModuleSignature as it's first argument.  
The second argument is the address of the function we want to go to with the hook.  
the third is the static variable you are going to store the return function at.

The first 3 types that can go into the first argument all assume that the AOB scan is going to take 
place in the main process module. If you need to scan a different module, add the base address of that 
module to ModuleSignature, and the scan will take place over that module.

the IDA string supports single `?` as one byte as well as `??` as one byte. It will also parse bytes that
are together up to 16 characters, like `20B4`, none of which can be a wild card. This feature might not last long, as 
there is a better pattern scanner I want to use, but I haven't implemented, yet. 

### IAT Hook
IAT hook takes the name of the module the function is in as the first argument.  
It takes the name of the function as the second argument.  
and it takes the address of the new function you want to execute.

You can add a null terminator to your strings, but it is enforced in the add_iat_hook method, so you
do not need to worry about it.

### GetProcAddress Hook
***You MUST have GetProcAddress hooked in some way for this to work.***

This will allow you to redirect any function calls that go through GetProcAddress on the targeted module.  
You will need to make a static mut variable to hold the hook. the `check_proc_addr_hook_bytes` function on the hook
takes in a slice, while the non bytes version takes a &str. That is the only difference.  

## Example
```rust
static mut HOOK: Option<Hook> = None; 

extern "system" fn get_proc_address_hook(module_handle: usize, proc_name: *const c_char) {
    let c_string = CStr::from_ptr(proc_name as *const c_char);
    println!("[!] GetProcAddress function: {:X?}", c_string);
    if let Some(hook) = &HOOK {
        if let Some(addr) = hook.check_proc_addr_hook_bytes(c_string.to_bytes_with_nul()) {
            return addr;
        }
    }
}
```

Altogether, you get a builder like this:
```rust
  fn hook() {
    unsafe {
        let mut hook = HookBuilder::new()
            .add_inline_hook(some_func as usize, some_func_hook as usize, &mut OG_SOME_FUNC)
            .add_iat_hook(
                "KERNEL32.dll",
                "GetProcAddress",
                get_proc_address_hook as usize,
            )
            .get_proc_address_hook("OpenFile", open_file as usize)
            .build();
        
        // If you are using GetProcAddress hook and you need to keep the hook around.  
        HOOK = Some(hook);
    }
}
```

