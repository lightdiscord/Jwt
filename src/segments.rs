// Copyright 2018 LightDiscord
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! Jwt segments

use base64;
use serde_json::{ self, Value };
use std::convert::Into;
use std::str::FromStr;
use super::{ Jwt, Payload, Signature, Result, Algorithm, ErrorKind };

/// Jwt segments
#[derive(Debug, Clone)]
pub struct Segments(pub Value, pub Payload, pub Signature);

impl Into<Result<Segments>> for Jwt {
    fn into (self) -> Result<Segments> {
        let Jwt(token) = self;
        let raw_segments: Vec<&str> = token.split(".").collect();
        if raw_segments.len() != 3 {
            bail!(ErrorKind::InvalidJwt);
        }

        let header = raw_segments[0];
        let header = base64::decode_config(&header, base64::URL_SAFE)?;
        let header = header.as_slice();
        let header: Value = serde_json::from_slice(header)?;

        let payload = raw_segments[1];
        let payload = base64::decode_config(&payload, base64::URL_SAFE)?;
        let payload = payload.as_slice();
        let payload = serde_json::from_slice(payload)?;
        let payload = Payload(payload);

        let algorithm = header["alg"].clone();
        let algorithm = algorithm.as_str().ok_or(ErrorKind::MissingAlgorithm)?;
        let algorithm = Algorithm::from_str(algorithm)?;

        let signature = raw_segments[2];
        let signature = Signature(signature.to_string(), algorithm);

        Ok(Segments(header, payload, signature))
    }
}
