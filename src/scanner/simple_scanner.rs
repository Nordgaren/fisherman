use crate::scanner::signature::Signature;
use std::ffi::c_void;

pub struct SimpleScanner;
// TY https://github.com/vswarte for your scan method in your AoB scanner for Broadsword!
impl SimpleScanner {
    pub fn scan(&self, scannable: &[u8], pattern: &Signature) -> Option<*mut c_void> {
        let mut position_in_pattern = 0;

        for (position, byte) in scannable.iter().enumerate() {
            if pattern.mask[position_in_pattern] != 0
                && pattern.signature[position_in_pattern] != *byte
            {
                position_in_pattern = 0;
                continue;
            }

            if position_in_pattern == pattern.length - 1 {
                return Some((position - pattern.length + 1) as *mut c_void);
            }

            position_in_pattern += 1;
        }

        None
    }
}
