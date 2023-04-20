use crate::scanner::signature::Signature;

pub struct SimpleScanner;
// TY Chainfailure for your scan method in your AoB scanner for Broadsword!
impl SimpleScanner {
    pub fn scan(&self, scannable: &[u8], pattern: &Signature) -> Option<usize> {
        let mut position_in_pattern = 0;

        for (position, byte) in scannable.iter().enumerate() {
            if pattern.mask[position_in_pattern] != 0
                && pattern.signature[position_in_pattern] != *byte
            {
                position_in_pattern = 0;
                continue;
            }

            if position_in_pattern == pattern.length - 1 {
                return Some(position - pattern.length + 1);
            }

            position_in_pattern += 1;
        }

        None
    }
}
