// # References
//
// "Hypertext Transfer Protocol (HTTP/1.1): Authentication" https://www.ietf.org/rfc/rfc7235.txt

use std::fmt;

use header::{Header, parsing};

/// The `WWW-Authenticate` header field.
#[derive(Clone, Debug, PartialEq)]
pub enum WWWAuthenticate {
    /// Basic authentication.
    Basic,

    /// Digest authentication
    Digest
}

impl Header for WWWAuthenticate {
    fn header_name() -> &'static str {
        static NAME: &'static str = "WWW-Authenticate";
        NAME
    }

    fn parse_header(raw: &[Vec<u8>]) -> ::Result<WWWAuthenticate> {
        parsing::from_one_raw_str(raw).and_then(|_s: String| {
            Ok(WWWAuthenticate::Basic)
        })
    }

    #[inline]
    fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl fmt::Display for WWWAuthenticate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Basic")
    }
}

#[cfg(test)]
mod tests {
    use super::{WWWAuthenticate};
    use ::header::Header;

    #[test]
    fn test_parse_header() {
        assert!(WWWAuthenticate::parse_header([b"".to_vec()].as_ref()).is_err());

        let a = [b"Basic".to_vec()];
        let a: WWWAuthenticate = WWWAuthenticate::parse_header(a.as_ref()).unwrap();
        let b = WWWAuthenticate::Basic;
        assert_eq!(a, b);
    }
}
