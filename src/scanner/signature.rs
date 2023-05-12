use std::ffi::c_void;
use std::fmt::{Debug, Formatter};

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

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:X?}", self.signature)?;
        Ok(())
    }
}

impl Debug for ModuleSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:X?}", self.signature.signature)?;
        Ok(())
    }
}

// TY https://github.com/vswarte for your from_ida_pattern method in your AoB scanner for Broadsword!
// Hope to use the real thing once the pattern matching is merged in!
impl Signature {
    pub fn from_ida_pattern(pattern: &str) -> Result<Self, ()> {
        let mut signature = Vec::new();
        let mut mask = Vec::new();

        for byte in pattern.split_whitespace() {
            if byte == "?" || byte == "??" {
                mask.push(0);
                signature.push(0);
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
                    5..=8 => signature.extend(
                        u32::from_str_radix(byte, 16)
                            .map_err(|_| {})?
                            .to_be_bytes()
                            .into_iter()
                            .skip_while(|b| *b == 0),
                    ),
                    9..=16 => signature.extend(
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

#[cfg(test)]
mod tests {
    use crate::scanner::signature::Signature;

    #[test]
    fn byte_string() {
        let sig = Signature::from_ida_pattern("F FF").unwrap();

        let mut sig_iter = sig.signature.iter();
        assert_eq!(sig_iter.next(), Some(&0xF));
        assert_eq!(sig_iter.next(), Some(&0xFF));
        assert_eq!(sig_iter.next(), None);

        let mut mask_iter = sig.mask.iter();
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), None);
    }

    #[test]
    fn short_string() {
        let sig = Signature::from_ida_pattern("FFF DD09").unwrap();

        let mut sig_iter = sig.signature.iter();
        assert_eq!(sig_iter.next(), Some(&0xF));
        assert_eq!(sig_iter.next(), Some(&0xFF));
        assert_eq!(sig_iter.next(), Some(&0xDD));
        assert_eq!(sig_iter.next(), Some(&0x09));
        assert_eq!(sig_iter.next(), None);

        let mut mask_iter = sig.mask.iter();
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), None);
    }

    #[test]
    fn int_string() {
        let sig = Signature::from_ida_pattern("D090000 DD090000").unwrap();

        let mut sig_iter = sig.signature.iter();
        assert_eq!(sig_iter.next(), Some(&0xD));
        assert_eq!(sig_iter.next(), Some(&0x9));
        assert_eq!(sig_iter.next(), Some(&0x00));
        assert_eq!(sig_iter.next(), Some(&0x00));
        assert_eq!(sig_iter.next(), Some(&0xDD));
        assert_eq!(sig_iter.next(), Some(&0x9));
        assert_eq!(sig_iter.next(), Some(&0x00));
        assert_eq!(sig_iter.next(), Some(&0x00));
        assert_eq!(sig_iter.next(), None);

        let mut mask_iter = sig.mask.iter();
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), None);
    }

    #[test]
    fn longlong_string() {
        let sig = Signature::from_ida_pattern("D090000DD090000 DD090000DD090000").unwrap();

        let mut sig_iter = sig.signature.iter();
        assert_eq!(sig_iter.next(), Some(&0xD));
        assert_eq!(sig_iter.next(), Some(&0x9));
        assert_eq!(sig_iter.next(), Some(&0x00));
        assert_eq!(sig_iter.next(), Some(&0x00));
        assert_eq!(sig_iter.next(), Some(&0xDD));
        assert_eq!(sig_iter.next(), Some(&0x9));
        assert_eq!(sig_iter.next(), Some(&0x00));
        assert_eq!(sig_iter.next(), Some(&0x00));
        assert_eq!(sig_iter.next(), Some(&0xDD));
        assert_eq!(sig_iter.next(), Some(&0x9));
        assert_eq!(sig_iter.next(), Some(&0x00));
        assert_eq!(sig_iter.next(), Some(&0x00));
        assert_eq!(sig_iter.next(), Some(&0xDD));
        assert_eq!(sig_iter.next(), Some(&0x9));
        assert_eq!(sig_iter.next(), Some(&0x00));
        assert_eq!(sig_iter.next(), Some(&0x00));
        assert_eq!(sig_iter.next(), None);

        let mut mask_iter = sig.mask.iter();
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), Some(&0xFF));
        assert_eq!(mask_iter.next(), None);
    }

    #[test]
    fn byte_string_too_long() {
        let sig = Signature::from_ida_pattern("FFFFFFFFFFFFFFFFF");
        assert!(matches!(sig.unwrap_err(), ()));
    }

    #[test]
    fn wildcard_in_multibyte_string() {
        let sig = Signature::from_ida_pattern("FF??");
        assert!(matches!(sig.unwrap_err(), ()));
    }
}
