use std::fmt::{Debug, Formatter};

pub struct Signature {
    pub signature: Vec<u8>,
    pub mask: Vec<u8>,
    pub length: usize,
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut string = String::new();
        for i in 0..self.signature.len() {
            if self.mask[i] == 0 {
                string.push_str("?? ")
            } else {
                string.push_str(&format!("{:02X} ", self.signature[i]))
            }
        }

        write!(f, "{}", string.trim())?;
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

    #[test]
    fn print_str() {
        let sig = Signature::from_ida_pattern("40 55 56 57 41 54 41 55 41 56 41 57 48 8D AC ?? ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 C7 45 ?? FE FF FF FF 48 89 9C ?? ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? 49 8B F9 4C 89 4C 24 ?? 44 89 44 24 ?? 48 8B F2 48 89 55 ?? 4C 8B E9 48 89 4C 24 ?? 48 8B 85 ?? ?? ?? ?? 48 89 44 24 ?? 48 8B 85 ?? ?? ?? ?? 48 89 45 ?? 32 ??");
        assert_eq!(&format!("{:?}", sig.unwrap()), "40 55 56 57 41 54 41 55 41 56 41 57 48 8D AC ?? ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 C7 45 ?? FE FF FF FF 48 89 9C ?? ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? 49 8B F9 4C 89 4C 24 ?? 44 89 44 24 ?? 48 8B F2 48 89 55 ?? 4C 8B E9 48 89 4C 24 ?? 48 8B 85 ?? ?? ?? ?? 48 89 44 24 ?? 48 8B 85 ?? ?? ?? ?? 48 89 45 ?? 32 ??")
    }
}
