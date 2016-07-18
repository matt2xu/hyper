// # References
//
// "Hypertext Transfer Protocol (HTTP/1.1): Authentication" https://www.ietf.org/rfc/rfc7235.txt

use std::any::Any;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::iter::{Enumerate, Peekable};
use std::str::Bytes;

use header::{Header, parsing};

/// The `WWW-Authenticate` header field.
#[derive(Clone, Debug, PartialEq)]
pub struct WwwAuthenticate<S: Scheme>(pub S);

impl<S: Scheme> Deref for WwwAuthenticate<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.0
    }
}

impl<S: Scheme> DerefMut for WwwAuthenticate<S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut self.0
    }
}

impl<S: Scheme + Any> Header for WwwAuthenticate<S> {
    fn header_name() -> &'static str {
        static NAME: &'static str = "WWW-Authenticate";
        NAME
    }

    fn parse_header(raw: &[Vec<u8>]) -> ::Result<WwwAuthenticate<S>> {
        parsing::from_one_raw_str(raw).and_then(|header: String| {
            for challenge in parse_challenges(&header) {
                let challenge = try!(challenge);
                let scheme = <S as Scheme>::scheme();
                if challenge.scheme() == scheme {
                    return match S::from_params(challenge.params()).map(WwwAuthenticate) {
                        Ok(h) => Ok(h),
                        Err(_) => Err(::Error::Header)
                    };
                }
            }

            Err(::Error::Header)
        })
    }

    fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let scheme = <S as Scheme>::scheme();
        try!(write!(f, "{} ", scheme));
        self.0.fmt_scheme(f)
    }
}

struct Challenge<'a> {
    scheme: &'a str,
    params: Vec<(&'a str, &'a str)>
}

impl<'a> Challenge<'a> {
    fn scheme(&self) -> &'a str {
        self.scheme
    }

    fn params(&self) -> &[(&'a str, &'a str)] {
        &self.params
    }
}

#[derive(Eq, PartialEq)]
enum Token<'a> {
    Ident(&'a str),
    String(&'a str),
    Comma,
    Equal
}

struct TokenIter<'a> {
    text: &'a str,
    iter: Peekable<Enumerate<Bytes<'a>>>
}

impl<'a> TokenIter<'a> {
    fn new(text: &'a str) -> TokenIter<'a> {
        TokenIter {
            text: text,
            iter: text.bytes().enumerate().peekable()
        }
    }
}

impl<'a> Iterator for TokenIter<'a> {
    type Item = Token<'a>;
    fn next(&mut self) -> Option<Token<'a>> {
        while let Some((begin, ch)) = self.iter.next() {
            match ch {
                b'=' => return Some(Token::Equal),
                b',' => return Some(Token::Comma),
                b' ' | b'\t' => continue,
                b'"' => {
                    while let Some((end, ch)) = self.iter.next() {
                        if ch == b'"' {
                            let slice = unsafe {self.text.slice_unchecked(begin + 1, end)};
                            return Some(Token::String(slice));
                        }
                    }

                    // malformed string
                    return None;
                }
                _ => {
                    // use peek so we don't eat the last character of the token
                    while let Some(&(end, ch)) = self.iter.peek() {
                        if ch == b' ' || ch == b'\t' || ch == b',' || ch == b'=' || ch == b'"' {
                            let slice = unsafe {self.text.slice_unchecked(begin + 1, end)};
                            return Some(Token::Ident(slice));
                        }
                        self.iter.next().unwrap();
                    }
                }
            }
        }
        None
    }
}

struct ChallengeIter<'a> {
    tokens: Peekable<TokenIter<'a>>
}

impl<'a> ChallengeIter<'a> {
    fn challenge(&mut self) -> Option<::Result<Challenge<'a>>> {
        let mut challenge = match self.tokens.next() {
            Some(Token::Ident(ident)) => Challenge {
                scheme: ident,
                params: vec![]
            },
            None => return None,
            Some(_) => return Some(Err(::Error::Header))
        };

        match self.tokens.next() {
            None | Some(Token::Comma) => {
                // the comma here is ambiguous
                // we interpret a ',' to mean the end of this challenge
                return Some(Ok(challenge))
            }
            Some(Token::Ident(ident)) => {
                if let Err(e) = self.add_params(&mut challenge.params, ident) {
                    return Some(Err(e));
                }
                Some(Ok(challenge))
            }
            _ => return Some(Err(::Error::Header))
        }
    }

    fn add_params(&mut self, params: &mut Vec<(&'a str, &'a str)>, mut key: &'a str) -> ::Result<()> {
        let mut state = 1;
        while let Some(token) = self.tokens.next() {
            match token {
                Token::Equal => {
                    state = 1;
                    self.tokens.next().unwrap();
                }
                Token::Ident(ident) | Token::String(ident) => {
                    if state == 1 {
                        params.push((key, ident));
                        state = 0;
                    } else {
                        key = ident;
                        state = 1;
                    }
                }
                Token::Comma => {
                    return Ok(());
                }
            }
        }

        Ok(())
    }
}

impl<'a> Iterator for ChallengeIter<'a> {
    type Item = ::Result<Challenge<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        while self.tokens.peek() == Some(&Token::Comma) {
            self.tokens.next().unwrap();
        }

        self.challenge()
    }
}

fn parse_challenges(text: &str) -> ChallengeIter {
    ChallengeIter {
        tokens: TokenIter::new(text).peekable()
    }
}

/// An Authorization scheme to be used in the header.
pub trait Scheme: fmt::Debug + Clone + Send + Sync {
    /// An optional Scheme name.
    ///
    /// Will be replaced with an associated constant once available.
    fn scheme() -> &'static str;
    /// Format the Scheme data into a header value.
    fn fmt_scheme(&self, &mut fmt::Formatter) -> fmt::Result;

    /// Creates a Scheme from a list of parameters.
    fn from_params(params: &[(&str, &str)]) -> ::Result<Self>;
}

/// Credential holder for Basic Authentication
#[derive(Clone, PartialEq, Debug)]
pub struct Basic {
    /// The username as a possibly empty string
    pub username: String,
    /// The password. `None` if the `:` delimiter character was not
    /// part of the parsed input.
    pub password: Option<String>
}

impl Scheme for Basic {
    fn scheme() -> &'static str {
        "Basic"
    }

    fn fmt_scheme(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Basic")
    }

    fn from_params(_params: &[(&str, &str)]) -> ::Result<Basic> {
        let basic = Basic {
            username: "foo".to_string(),
            password: Some("bar".to_string())
        };
        Ok(basic)
    }
}

impl fmt::Display for WwwAuthenticate<Basic> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Basic")
    }
}

#[cfg(test)]
mod tests {
    use super::{WwwAuthenticate};
    use ::header::Header;

    #[test]
    fn test_parse_header() {
        assert!(WwwAuthenticate::parse_header([b"".to_vec()].as_ref()).is_err());

        let a = [b"Basic".to_vec()];
        let a: WwwAuthenticate = WwwAuthenticate::parse_header(a.as_ref()).unwrap();
        let b = WwwAuthenticate::Basic;
        assert_eq!(a, b);
    }

    //
    // WWW-Authenticate: Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple"
}
