// Copyright 2018 LightDiscord
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! # Jwt
//!
//! Another JWT implementation written in Rust

#![deny(missing_docs, unsafe_code, unused_extern_crates, warnings)]

extern crate openssl;
#[macro_use] extern crate error_chain;

use std::borrow::Cow;

pub mod algorithm;
pub mod error;

pub use error::Error;

/// A Simple Jwt
#[derive(Debug)]
pub struct Jwt<'jwt>(Cow<'jwt, str>);

impl<'jwt> Jwt<'jwt> {
    /// Create a Jwt from any type who can be turned into a `Cow<'jwt, str>`
    pub fn new<S>(raw: S) -> Self where S: Into<Cow<'jwt, str>> {
        Jwt(raw.into())
    }
}

/// Transform something into Jwt's parts
pub trait IntoParts<'c> {
    /// Error type from a convertion
    type Error;

    /// Convert it!
    fn into_parts (&'c self) -> Result<Parts, Self::Error>;
}

impl<'jwt> IntoParts<'jwt> for Jwt<'jwt> {
    type Error = ();

    fn into_parts (&'jwt self) -> Result<Parts, Self::Error> {
        let parts: Vec<&'jwt str> = self.0.split(".").collect();

        if parts.len() != 3 {
            unimplemented!()
        }

        let parts = Parts {
            header: Header::new(parts[0]),
            payload: Payload::new(parts[1]),
            signature: Signature::new(parts[2])
        };

        Ok(parts)
    }
}

/// Jwt's parts
#[derive(Debug)]
pub struct Parts<'h, 'p, 's> {
    header: Header<'h>,
    payload: Payload<'p>,
    signature: Signature<'s>
}

/// Jwt's header
#[derive(Debug)]
pub struct Header<'h>(Cow<'h, str>);

impl<'h> Header<'h> {
    /// Create a Jwt's header from any type who can be turned into a `Cow<'h, str>`
    pub fn new<S>(raw: S) -> Self where S: Into<Cow<'h, str>> {
        Header(raw.into())
    }
}

/// Jwt's payload
#[derive(Debug)]
pub struct Payload<'p>(Cow<'p, str>);

impl<'p> Payload<'p> {
    /// Create a Jwt's payload from any type who can be turned into a `Cow<'p, str>`
    pub fn new<S>(raw: S) -> Self where S: Into<Cow<'p, str>> {
        Payload(raw.into())
    }
}

/// Jwt's signature
#[derive(Debug)]
pub struct Signature<'s>(Cow<'s, str>);

impl<'s> Signature<'s> {
    /// Create a Jwt's signature from any type who can be turned into a `Cow<'s, str>`
    pub fn new<S>(raw: S) -> Self where S: Into<Cow<'s, str>> {
        Signature(raw.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{ Jwt, IntoParts };

    #[test]
    fn jwt_from_str () {
        let s = test_jwt();
        let jwt = Jwt::new(s);

        assert_eq!(jwt.0.into_owned(), String::from(s));
    }

    #[test]
    fn jwt_from_string () {
        let s = test_jwt();
        let s = String::from(s);
        let jwt = Jwt::new(s.clone());

        assert_eq!(jwt.0.into_owned(), s);
    }

    #[test]
    fn jwt_into_parts () {
        let s = test_jwt();
        let jwt = Jwt::new(s);
        let parts = jwt.into_parts();

        println!("{:?}", parts);
    }

    fn test_jwt () -> &'static str {
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJGQkkhIGN1eicgaXQncyBzZWNyZXQhIHNodXQhIiwiZXhwIjoxNTE5OTk0NTAxLCJoZWxsbyI6IndvcmxkIiwiaWF0IjoxNTE5OTk0NDkxLCJpc3MiOiJUZXN0LW1hbiEiLCJsaWdodCI6ImRpc2NvcmQifQ==.gS76BWOStsnrG9nMacQQE7ThHM1UIR2omB6YkBaQjZ0="
    }
}

/*
//extern crate serde;
extern crate base64;
extern crate openssl;

#[macro_use]
extern crate error_chain;

#[macro_use]
extern crate serde_json;

use serde_json::Value as JsonValue;

pub mod error;
use error::*;

pub mod algorithm;
use algorithm::Algorithm;

pub mod signature;
use signature::{ Signature, AsKey };

pub mod claims;
use claims::RegisteredClaims;

pub mod segments;
use segments::{ Segments, Payload, Header };

pub mod verification;
use verification::Verifications;

use std::borrow::Cow;

const STANDARD_HEADER_TYPE: &str = "JWT";

/// A simple Jwt
#[derive(Debug, Clone)]
pub struct Jwt<'jwt>(pub Cow<'jwt, str>);

impl<'jwt> Jwt<'jwt> {
    pub fn new<S>(raw: S) -> Self where S: Into<Cow<'jwt, str>> {
        Jwt(raw.into())
    }

    /// Encode data into a Jwt
    pub fn encode<P: AsKey>(
        header: &Header,
        payload: &Payload,
        signing_key: &P,
        algorithm: Algorithm,
    ) -> error::Result<Self> {
        let Header(mut header) = header.clone();
        header["alg"] = JsonValue::String(algorithm.to_string());
        header["typ"] = JsonValue::String(STANDARD_HEADER_TYPE.to_owned());
        let header = Header(header);

        let sign = format!("{}.{}", header, payload);

        let signature = match algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                Signature::hmac(&sign, signing_key, algorithm)?
            }
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                Signature::rsa(&sign, signing_key, algorithm)?
            }
            Algorithm::ES256 | Algorithm::ES384 | Algorithm::ES512 => {
                Signature::es(&sign, signing_key, algorithm)?
            }
        };

        let token = Jwt::new(format!("{}.{}", sign, signature));

        Ok(token)
    }

    /// Decode Token from a jwt
    pub fn decode<P: AsKey>(&self, signing_key: &P) -> Result<Segments> {
        let segments: Result<Segments> = self.clone().into();
        let Segments(header, payload, signature) = segments?;

        let combinaison = format!("{}.{}", header, payload);

        println!("{:?}", signature);

        if !signature.verify(combinaison, signing_key)? {
            bail!(ErrorKind::InvalidSignature);
        } else {
            Ok(Segments(header, payload, signature))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::path::PathBuf;
    use std::time::{ SystemTime, UNIX_EPOCH };
    use super::{ Jwt, Algorithm, Payload, RegisteredClaims, Header, Verifications, Segments };

    #[test]
    fn test_sign_hs256 () {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let payload = json!({
            "hello": "world",
            "light": "discord"
        });
        let payload = Payload(payload);
        let payload = payload.apply(vec![
            RegisteredClaims::Issuer("Test-man!".to_string()),
            RegisteredClaims::Audience("FBI! cuz' it's secret! shut!".to_string()),
            RegisteredClaims::IssuedAt(now),
            RegisteredClaims::ExpirationTime(now + 10)
        ]);

        let secret = "This is super mega secret!".to_string();
        let header = Header(json!({}));

        let jwt = Jwt::encode(&header, &payload, &secret, Algorithm::HS256).unwrap();
        println!("{:?}", jwt);

        let result = jwt.decode(&secret);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_valid_jwt_hs256 () {
        let secret = "This is super mega secret!".to_string();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIiwibGlnaHQiOiJkaXNjb3JkIn0=.cDX7rt5fNUG9itlV--5R6hzuNM4yrVR6DiQytrCdoRw=".to_string();
        let jwt = Jwt::new(jwt);
        let result = jwt.decode(&secret);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_invalid_jwt_hs256 () {
        let secret = "This is super secret!".to_string();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIiwibGlnaHQiOiJkaXNjb3JkIn0=.cDX7rt5fNUG9itlV--5R6hzuNM4yrVR6DiQytrCdoRw=".to_string();
        let jwt = Jwt::new(jwt);
        let result = jwt.decode(&secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_rs256 () {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let payload = json!({
            "hello": "world",
            "light": "discord"
        });
        let payload = Payload(payload);
        let payload = payload.apply(vec![
            RegisteredClaims::Issuer("Test-man!".to_string()),
            RegisteredClaims::Audience("FBI! cuz' it's secret! shut!".to_string()),
            RegisteredClaims::IssuedAt(now),
            RegisteredClaims::ExpirationTime(now + 10)
        ]);
        let header = Header(json!({}));

        let private_key = rsa_private_key();
        let public_key = rsa_public_key();

        let jwt = Jwt::encode(&header, &payload, &private_key, Algorithm::RS256).unwrap();
        println!("{:?}", jwt);

        let result = jwt.decode(&public_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_valid_jwt_rs256 () {
        let public_key = rsa_public_key();
        let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJGQkkhIGN1eicgaXQncyBzZWNyZXQhIHNodXQhIiwiaGVsbG8iOiJ3b3JsZCIsImlzcyI6IlRlc3QtbWFuISIsImxpZ2h0IjoiZGlzY29yZCJ9.iJ7xzImxSBFKYzYpI-iApq1gAV-nP1ibr3A8oB4-IDsDPWoOTNrgxAzeiZaH9qU3GgQ_gnd-DvlCz950zdP2LSRuusoO7hQC2VHcChje630Lb5HH-IdnDwYPJoblkmSGdaVv6c670c49QwvIhF8qILg1DWoc14uFeXDyNTADroWnCYqWem8gcD4yybrdbPlBNJbVKKCJIp1-wRpZ5U6jIclvwV0tuKTjsZPCgNBGkgL-b9qdofeZw52eXBoW3nXTKa9FvLzavi_moyT79PVzFZACE0mqRBM9E80RSkvCd21HxkzcaN-7pslLWiRkAIkfU0jJWBQZU5x_k6HIyl8whg==".to_string();
        let jwt = Jwt::new(jwt);
        let result = jwt.decode(&public_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_expired_jwt_rs256 () {
        let public_key = rsa_public_key();
        let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJGQkkhIGN1eicgaXQncyBzZWNyZXQhIHNodXQhIiwiZXhwIjoxNTE5OTk0NTAxLCJoZWxsbyI6IndvcmxkIiwiaWF0IjoxNTE5OTk0NDkxLCJpc3MiOiJUZXN0LW1hbiEiLCJsaWdodCI6ImRpc2NvcmQifQ==.UqoZACmQeU3Cr1mcvMLdzqErJs_JaC7KClxDgQtt_J2d5dH_YCUzS11w0xE5Q09Ba7nA1UW3xgW6NYTpRNTnHETROJxPJ4GsTfyhLKbtFAoZy78VbLmXOpYvY1abF5dWxICJjY6sARUGajiZEK827Yt6Iiom0Mq0lwuuraW9xWLZjpZNuq1TDy5FuZRwx-fIPpo3_okHZoN5g3hrW_uTLqlsjJlotFvyfXJDhS1xPmyPjl1bH3ljuMv1HrTEOe3Gep1a0Mmbu3cjq9zee1fb46rrgpogap4N_DuLSJrgDvY7MVOXDNYAgllijeVhD2Xr1shCW8sIJ3RDaoQME5YW3Q==".to_string();
        let jwt = Jwt::new(jwt);
        let result = jwt.decode(&public_key).unwrap();
        let Segments(_, payload, _) = result;

        let result = payload.verify(vec![
            Verifications::SameClaim(RegisteredClaims::Issuer("Test-man!".to_string())),
            Verifications::Expired
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn test_decode_invalid_jwt_rs256 () {
        let public_key = rsa_public_key();
        let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJGQkkhIGN1eicgaXQncyBzZWNyZXQhIHNodXQhIiwiaGVsbG8iOiJ3b3JsZCIsImlzcyI6IlRlc3QtbWFuISIsImxpZ2h0IjoicGFzIGRpc2NvcmQifQ.iJ7xzImxSBFKYzYpI-iApq1gAV-nP1ibr3A8oB4-IDsDPWoOTNrgxAzeiZaH9qU3GgQ_gnd-DvlCz950zdP2LSRuusoO7hQC2VHcChje630Lb5HH-IdnDwYPJoblkmSGdaVv6c670c49QwvIhF8qILg1DWoc14uFeXDyNTADroWnCYqWem8gcD4yybrdbPlBNJbVKKCJIp1-wRpZ5U6jIclvwV0tuKTjsZPCgNBGkgL-b9qdofeZw52eXBoW3nXTKa9FvLzavi_moyT79PVzFZACE0mqRBM9E80RSkvCd21HxkzcaN-7pslLWiRkAIkfU0jJWBQZU5x_k6HIyl8whg==".to_string();
        let jwt = Jwt::new(jwt);
        let result = jwt.decode(&public_key);
        assert!(result.is_err());
    }

    fn rsa_public_key () -> PathBuf {
        let mut base_path = env::current_dir().unwrap();
        base_path.push("resources");
        base_path.push("rsa.pub");

        base_path
    }

    fn rsa_private_key () -> PathBuf {
        let mut base_path = env::current_dir().unwrap();
        base_path.push("resources");
        base_path.push("rsa.private.key");

        base_path
    }
}
*/
