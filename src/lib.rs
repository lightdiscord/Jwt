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

#[cfg(test)]
#[macro_use]
extern crate serde_json;

#[cfg(not(test))]
extern crate serde_json;

use serde_json::Value as JsonValue;

pub mod error;
use error::*;

pub mod algorithm;
use algorithm::Algorithm;

pub mod signature;
use signature::{ Signature, AsKey };

const STANDARD_HEADER_TYPE: &str = "JWT";

/// A simple Jwt
#[derive(Debug)]
pub struct Jwt(pub String);

impl Jwt {
    /// Encode data into a Jwt
    pub fn encode<P: AsKey>(
        header: JsonValue,
        payload: &JsonValue,
        signing_key: &P,
        algorithm: Algorithm,
    ) -> error::Result<Self> {
        let mut header = header.clone();
        header["alg"] = JsonValue::String(algorithm.to_string());
        header["typ"] = JsonValue::String(STANDARD_HEADER_TYPE.to_owned());
        let header = header;

        let header = serde_json::to_string(&header)?;
        let header = ::base64::encode_config(header.as_bytes(), ::base64::URL_SAFE);

        let payload = serde_json::to_string(&payload)?;
        let payload = ::base64::encode_config(payload.as_bytes(), ::base64::URL_SAFE);

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
    pub fn decode<P: AsKey>(&self, signing_key: &P, algorithm: Algorithm) -> Result<(JsonValue, JsonValue)> {
        let (header, payload, signature, input) = decode_segments(self)?;
        let signature = Signature(base64::encode_config(&signature.clone(), base64::URL_SAFE), algorithm);
        println!("{:?}", signature);

        if !signature.verify(input, signing_key)? {
            bail!(ErrorKind::InvalidSignature);
        } else {
            Ok((header, payload))
        }
    }
}

fn decode_segments (token: &Jwt) -> Result<(JsonValue, JsonValue, Vec<u8>, String)> {
    let &Jwt(ref token) = token;
    let raw_segments: Vec<&str> = token.split(".").collect();
    if raw_segments.len() != 3 {
        bail!(ErrorKind::InvalidJwt);
    }

    let header = raw_segments[0];
    let payload = raw_segments[1];
    let input = format!("{}.{}", header, payload);

    let header = base64::decode_config(&header, base64::URL_SAFE)?;
    let header = header.as_slice();
    let header = serde_json::from_slice(header)?;

    let payload = base64::decode_config(&payload, base64::URL_SAFE)?;
    let payload = payload.as_slice();
    let payload = serde_json::from_slice(payload)?;

    let signature = raw_segments[2];
    let signature = base64::decode_config(signature.as_bytes(), base64::URL_SAFE)?;

    Ok((header, payload, signature, input))
}

#[cfg(test)]
mod tests {
    use super::{ Jwt, Algorithm };

    #[test]
    fn test_sign_hs256 () {
        let payload = json!({
            "hello": "world",
            "light": "discord"
        });

        let secret = "This is super mega secret!".to_string();
        let header = json!({});

        let jwt = Jwt::encode(header, &payload, &secret, Algorithm::HS256).unwrap();
        println!("{:?}", jwt);

        let result = jwt.decode(&secret, Algorithm::HS256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_valid_jwt_hs256 () {
        let secret = "This is super mega secret!".to_string();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIiwibGlnaHQiOiJkaXNjb3JkIn0=.cDX7rt5fNUG9itlV--5R6hzuNM4yrVR6DiQytrCdoRw=".to_string();
        let result = Jwt(jwt).decode(&secret, Algorithm::HS256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_invalid_jwt_hs256 () {
        let secret = "This is super secret!".to_string();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIiwibGlnaHQiOiJkaXNjb3JkIn0=.cDX7rt5fNUG9itlV--5R6hzuNM4yrVR6DiQytrCdoRw=".to_string();
        let result = Jwt(jwt).decode(&secret, Algorithm::HS256);
        assert!(result.is_err());
    }
}
