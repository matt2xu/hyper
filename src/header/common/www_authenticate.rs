// # References
//
// "Hypertext Transfer Protocol (HTTP/1.1): Authentication" https://www.ietf.org/rfc/rfc7235.txt

use std::any::Any;
use std::borrow::Cow;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::iter::{Peekable};
use std::str::Split;

use serialize::base64::FromBase64;
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
                    return match S::from_info(challenge.info()).map(WwwAuthenticate) {
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
    scheme: Cow<'a, str>,
    info: Option<ChallengeInfo<'a>>
}

#[derive(Debug)]
pub enum ChallengeInfo<'a> {
    Base64(Cow<'a, str>),
    Params(Vec<(Cow<'a, str>, Cow<'a, str>)>)
}

impl<'a> Challenge<'a> {
    fn scheme(&'a self) -> &'a str {
        &self.scheme
    }

    fn info(&self) -> Option<&ChallengeInfo<'a>> {
        self.info.as_ref()
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Token<'a> {
    Text(Cow<'a, str>),
    Equal
}

struct TokenIter<'a> {
    text: &'a str,
    position: usize
}

impl<'a> TokenIter<'a> {
    fn new(text: &'a str) -> TokenIter<'a> {
        TokenIter {
            text: text,
            position: 0
        }
    }

    fn next_char(&mut self) -> Option<(usize, u8)> {
        let bytes = self.text.as_bytes();
        if self.position < bytes.len() {
            let result = Some((self.position, unsafe {*bytes.get_unchecked(self.position)}));
            self.position += 1;
            result
        } else {
            None
        }
    }

    /// Returns a borrowed slice of `self.text` with the given range.
    fn slice(&mut self, begin: usize, end: usize) -> Cow<'a, str> {
        Cow::Borrowed(unsafe {self.text.slice_unchecked(begin, end)})
    }

    /// Parses a token or token68.
    ///
    /// Note: in this function the range of characters is inclusive
    /// (as opposed to next_string).
    fn next_ident(&mut self, begin: usize) -> Option<Token<'a>> {
        let mut end = begin;
        while let Some((index, ch)) = self.next_char() {
            match ch {
                b'=' => {
                    end = self.next_ident_or_token68(index);
                    break;
                }
                b' ' | b'\t' | b'"' => {
                    end = index - 1;
                    break;
                }
                _ => { end = index; }
            }
        }

        Some(Token::Text(self.slice(begin, end + 1)))
    }

    /// Returns the position of the last character (inclusive) of this token.
    ///
    /// Peeks at characters after the last equal sign to disambiguate between
    /// token and token68 rules.
    fn next_ident_or_token68(&mut self, first_equal_index: usize) -> usize {
        let mut last_equal_index = first_equal_index;
        let mut whitespace = false;
        while let Some((index, ch)) = self.next_char() {
            match ch {
                b'=' => {
                    if whitespace {
                        // syntax error, go back and leave
                        self.position = last_equal_index + 1;
                        break;
                    }
                    last_equal_index = index;
                }
                b' ' | b'\t' => {
                    // to know that this is no longer a series of '='
                    whitespace = true;
                }
                _ => { // beginning of a token or quoted string, go back to the first equal sign
                    self.position = first_equal_index;
                    return first_equal_index - 1;
                }
            }
        }

        last_equal_index
    }

    /// Parses a quoted-string.
    ///
    /// Returns a borrowed &str unless the string contains a quoted-pair,
    /// in which case returns an owned String.
    fn next_string(&mut self, begin: usize) -> Option<Token<'a>> {
        let begin = begin + 1;
        let mut owned = None;
        while let Some((end, mut ch)) = self.next_char() {
            match ch {
                b'"' => {
                    return Some(Token::Text(match owned {
                        None => self.slice(begin, end),
                        Some(string) => Cow::Owned(string)
                    }));
                }
                b'\\' => {
                    if owned.is_none() {
                        owned = Some(self.slice(begin, end).into_owned());
                    }

                    if let Some((_, escaped)) = self.next_char() {
                        ch = escaped;
                    } else {
                        break;
                    }
                },
                _ => ()
            }

            if let Some(ref mut string) = owned {
                string.push(ch as char);
            }
        }

        // malformed string
        None
    }
}

impl<'a> Iterator for TokenIter<'a> {
    type Item = Token<'a>;
    fn next(&mut self) -> Option<Token<'a>> {
        while let Some((index, ch)) = self.next_char() {
            let token = match ch {
                b' ' | b'\t' => continue,
                b'=' => Some(Token::Equal),
                b'"' => self.next_string(index),
                _ => self.next_ident(index)
            };
            println!("{:?}", token);
            return token;
        }
        None
    }
}

struct ChallengeIter<'a> {
    iter: Peekable<Filtered<'a>>
}

struct Filtered<'a> {
    iter: Split<'a, char>
}

impl<'a> Iterator for Filtered<'a> {
    type Item = &'a str;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        for entry in self.iter.by_ref() {
            let trimmed = entry.trim();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
        None
    }
}

impl<'a> ChallengeIter<'a> {
    fn challenge(&mut self, entry: &'a str) -> Option<::Result<Challenge<'a>>> {
        let mut tokens = TokenIter::new(entry);
        let mut challenge = match tokens.next() {
            None => return None,
            Some(Token::Equal) => return Some(Err(::Error::Header)),
            Some(Token::Text(ident)) => Challenge {
                scheme: ident,
                info: None
            },
        };

        Some(match tokens.next() {
            None => Ok(challenge),
            Some(Token::Equal) => Err(::Error::Header),
            Some(Token::Text(ident)) =>
                self.info(&mut tokens, ident).map(|info| {
                    challenge.info = Some(info);
                    challenge
                })
        })
    }

    fn info(&mut self, tokens: &mut TokenIter<'a>, ident: Cow<'a, str>) -> ::Result<ChallengeInfo<'a>> {
        match tokens.next() {
            None => Ok(ChallengeInfo::Base64(ident)),
            Some(Token::Text(_)) => Err(::Error::Header),
            Some(Token::Equal) =>
                if let Some(Token::Text(value)) = tokens.next() {
                    // extra tokens are a syntax error
                    if tokens.next().is_some() {
                        return Err(::Error::Header);
                    }

                    let mut params = vec![(ident, value)];
                    self.add_params(&mut params).map(|_| ChallengeInfo::Params(params))
                } else {
                    Err(::Error::Header)
                }
        }
    }

    /// Parses auth-params until the beginning of the next challenge.
    fn add_params(&mut self, params: &mut Vec<(Cow<'a, str>, Cow<'a, str>)>) -> ::Result<()> {
        while let Some(&entry) = self.iter.peek() {
            let mut tokens = TokenIter::new(entry);
            if let Some(Token::Text(key)) = tokens.next() {
                match tokens.next() {
                    None | Some(Token::Text(_)) => {
                        // auth-scheme alone or followed by a token/token68
                        break;
                    }
                    Some(Token::Equal) => {
                        if let Some(Token::Text(value)) = tokens.next() {
                            // make sure there are no extra tokens
                            if tokens.next().is_none() {
                                params.push((key, value));

                                // advance the iterator and continue parsing
                                self.iter.next().unwrap();
                                continue;
                            }
                        }
                    }
                }
            }

            // fallthrough error
            return Err(::Error::Header);
        }

        Ok(())
    }
}

impl<'a> Iterator for ChallengeIter<'a> {
    type Item = ::Result<Challenge<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(entry) = self.iter.next() {
            println!("entry: \"{}\"", entry);
            self.challenge(entry)
        } else {
            None
        }
    }
}

fn parse_challenges(text: &str) -> ChallengeIter {
    ChallengeIter {
        iter: Filtered {iter: text.split(',')}.peekable()
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

    /// Creates a Scheme from challenge information.
    fn from_info<'a>(info: Option<&ChallengeInfo<'a>>) -> ::Result<Self>;
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

    fn from_info<'a>(info: Option<&ChallengeInfo<'a>>) -> ::Result<Basic> {
        if let Some(&ChallengeInfo::Base64(ref base64)) = info {
            println!("base64 info: {:?}", base64);
            match base64.from_base64() {
                Ok(decoded) => match String::from_utf8(decoded) {
                    Ok(text) => {
                        let mut parts = &mut text.split(':');
                        let user = match parts.next() {
                            Some(part) => part.to_owned(),
                            None => return Err(::Error::Header)
                        };
                        let password = match parts.next() {
                            Some(part) => Some(part.to_owned()),
                            None => None
                        };
                        println!("username: {:?}", user);
                        println!("password: {:?}", password);
                        Ok(Basic {
                            username: user,
                            password: password
                        })
                    },
                    Err(e) => {
                        debug!("Basic::from_utf8 error={:?}", e);
                        Err(::Error::Header)
                    }
                },
                Err(e) => {
                    debug!("Basic::from_base64 error={:?}", e);
                    Err(::Error::Header)
                }
            }
        } else {
            Err(::Error::Header)
        }
    }
}

impl fmt::Display for WwwAuthenticate<Basic> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Basic")
    }
}

#[cfg(test)]
mod tests {
    use super::{WwwAuthenticate, Basic, parse_challenges};
    use ::header::Header;

    #[test]
    fn test_parse_header() {
        // assert!(WwwAuthenticate::parse_header([b"".to_vec()].as_ref()).is_err());

        parse_challenges("Basic x=,Digest").count();
        parse_challenges("Basic x=  =,Digest").count();
        parse_challenges("Basic x==,Digest").count();
        parse_challenges("Basic x=    ,Digest").count();
        parse_challenges("Basic x==   ,Digest").count();
        parse_challenges("Basic a=b,   Digest").count();
        parse_challenges("Basic aa=bb,   Digest").count();
        parse_challenges("Basic b=\"a\",   Digest").count();
        parse_challenges("Basic bb=\"aa\",   Digest").count();
        parse_challenges("Basic x=    a  ,   Digest").count();
        parse_challenges(r#"Basic x=    "a \"quoted\" pair",Digest"#).count();

        let a = [b"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==".to_vec()];
        let a: WwwAuthenticate<Basic> = WwwAuthenticate::parse_header(a.as_ref()).unwrap();
        let b = Basic {
            username: "Aladdin".to_string(),
            password: Some("open sesame".to_string())
        };
        assert_eq!(*a, b);
    }

    //
    // WWW-Authenticate: Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple"
}
