// # References
//
// "Hypertext Transfer Protocol (HTTP/1.1): Authentication" https://www.ietf.org/rfc/rfc7235.txt

use std::any::Any;
use std::borrow::Cow;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::iter::{Peekable};

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
    params: Vec<(Cow<'a, str>, Cow<'a, str>)>
}

impl<'a> Challenge<'a> {
    fn scheme(&self) -> &'a str {
        self.scheme
    }

    fn params(&self) -> &[(Cow<'a, str>, Cow<'a, str>)] {
        &self.params
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Token<'a> {
    Ident(&'a str),
    String(Cow<'a, str>),
    Comma,
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

    fn slice(&mut self, begin: usize, end: usize) -> &'a str {
        unsafe {self.text.slice_unchecked(begin, end)}
    }

    fn next_ident(&mut self, begin: usize) -> Option<Token<'a>> {
        let mut end = begin;
        while let Some((index, ch)) = self.next_char() {
            match ch {
                b'=' => {
                    end = self.next_ident_or_token68(index);
                    break;
                }
                b' ' | b'\t' | b',' | b'"' => {
                    end = index;
                    break;
                }
                _ => { end = index + 1; }
            }
        }

        Some(Token::Ident(self.slice(begin, end)))
    }

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
                b',' => { // token68, go back to the comma
                    self.position = index;
                    break;
                }
                _ => { // beginning of a token or quoted string, go back to the first equal sign
                    self.position = first_equal_index;
                    return first_equal_index;
                }
            }
        }

        last_equal_index + 1
    }

    fn next_string(&mut self, begin: usize) -> Option<Token<'a>> {
        let begin = begin + 1;
        while let Some((end, ch)) = self.next_char() {
            match ch {
                b'"' => return Some(Token::String(Cow::Borrowed(self.slice(begin, end)))),
                b'\\' => {
                    let mut string = self.slice(begin, end).to_owned();
                    if let Some((_, ch)) = self.next_char() {
                        string.push(ch as char);
                    } else {
                        break;
                    }

                    return self.next_string_owned(string);
                },
                _ => ()
            }
        }

        // malformed string
        None
    }

    /// owned version of next_string, used when the quoted-string contains a quoted-pair
    fn next_string_owned(&mut self, mut string: String) -> Option<Token<'a>> {
        while let Some((_, ch)) = self.next_char() {
            match ch {
                b'"' => return Some(Token::String(Cow::Owned(string))),
                b'\\' => {
                    if let Some((_, ch)) = self.next_char() {
                        string.push(ch as char);
                    } else {
                        break;
                    }
                }
                _ => string.push(ch as char)
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
            match ch {
                b'=' => return Some(Token::Equal),
                b',' => return Some(Token::Comma),
                b' ' | b'\t' => continue,
                b'"' => return self.next_string(index),
                _ => return self.next_ident(index)
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

    fn add_params(&mut self, params: &mut Vec<(Cow<'a, str>, Cow<'a, str>)>, ident: &'a str) -> ::Result<()> {
        let mut state = 1;
        let mut key = Some(Cow::Borrowed(ident));
        while let Some(token) = self.tokens.next() {
            match token {
                Token::Equal => {
                    state = 1;
                    self.tokens.next().unwrap();
                }
                Token::Ident(ident) => {
                    if state == 1 {
                        params.push((key.take().unwrap(), Cow::Borrowed(ident)));
                        state = 0;
                    } else {
                        key = Some(Cow::Borrowed(ident));
                        state = 1;
                    }
                }
                Token::String(cow) => {
                    if state == 1 {
                        params.push((key.take().unwrap(), cow));
                        state = 0;
                    } else {
                        key = Some(cow);
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
    fn from_params<'a>(params: &[(Cow<'a, str>, Cow<'a, str>)]) -> ::Result<Self>;
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

    fn from_params<'a>(_params: &[(Cow<'a, str>, Cow<'a, str>)]) -> ::Result<Basic> {
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
    use super::{WwwAuthenticate, Basic, TokenIter};
    use ::header::Header;

    #[test]
    fn test_parse_header() {
        // assert!(WwwAuthenticate::parse_header([b"".to_vec()].as_ref()).is_err());

        for token in TokenIter::new("Basic x=,Digest") {
            println!("{:?}", token);
        }

        for token in TokenIter::new("Basic x=  =,Digest") {
            println!("{:?}", token);
        }

        for token in TokenIter::new("Basic x==,Digest") {
            println!("{:?}", token);
        }

        for token in TokenIter::new("Basic x=    ,Digest") {
            println!("{:?}", token);
        }

        for token in TokenIter::new("Basic x==   ,Digest") {
            println!("{:?}", token);
        }

        for token in TokenIter::new("Basic x=    a  ,   Digest") {
            println!("{:?}", token);
        }

        for token in TokenIter::new(r#"Basic x=    "a \"quoted\" pair",Digest"#) {
            println!("{:?}", token);
        }

        let a = [b"Basic".to_vec()];
        let a: WwwAuthenticate<Basic> = WwwAuthenticate::parse_header(a.as_ref()).unwrap();
        let b = Basic {
            username: "login".to_string(),
            password: Some("password".to_string())
        };
        assert_eq!(*a, b);
    }

    //
    // WWW-Authenticate: Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple"
}
