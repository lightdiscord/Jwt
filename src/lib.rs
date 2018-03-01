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

pub mod default;
use default::RegisteredClaims;

pub mod segments;
use segments::{ Segments, Payload, Header };

const STANDARD_HEADER_TYPE: &str = "JWT";

/// A simple Jwt
#[derive(Debug, Clone)]
pub struct Jwt(pub String);

impl Jwt {
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

        let token = Jwt(format!("{}.{}", sign, signature));

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
    use super::{ Jwt, Algorithm, Payload, RegisteredClaims, Header };

    #[test]
    fn test_sign_hs256 () {
        let payload = json!({
            "hello": "world",
            "light": "discord"
        });
        let payload = Payload(payload);
        let payload = payload.apply(vec![
            RegisteredClaims::Issuer("Test-man!".to_string()),
            RegisteredClaims::Audience("FBI! cuz' it's secret! shut!".to_string())
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
        let result = Jwt(jwt).decode(&secret);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_invalid_jwt_hs256 () {
        let secret = "This is super secret!".to_string();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIiwibGlnaHQiOiJkaXNjb3JkIn0=.cDX7rt5fNUG9itlV--5R6hzuNM4yrVR6DiQytrCdoRw=".to_string();
        let result = Jwt(jwt).decode(&secret);
        assert!(result.is_err());
    }
}
