// Copyright 2018 LightDiscord
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! Algorithms used for Jwt signature

use std::convert::Into;
use openssl::hash::MessageDigest;

/// Different algorithms use to sign a jwt
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// HMAC with SHA-256
    HS256,

    /// HMAC with SHA-384
    HS384,

    /// HMAC with SHA-512
    HS512,

    /// RSA Signature with SHA-256
    RS256,

    /// RSA Signature with SHA-384
    RS384,

    /// RSA Signature with SHA-512
    RS512,

    /// ECDSA with SHA-256
    ES256,

    /// ECDSA with SHA-256
    ES384,

    /// ECDSA with SHA-256
    ES512,
}

impl Into<MessageDigest> for Algorithm {
    fn into (self) -> MessageDigest {
        match self {
            Algorithm::HS256 => MessageDigest::sha256(),
            Algorithm::RS256 => MessageDigest::sha256(),
            Algorithm::ES256 => MessageDigest::sha256(),

            Algorithm::HS384 => MessageDigest::sha384(),
            Algorithm::RS384 => MessageDigest::sha384(),
            Algorithm::ES384 => MessageDigest::sha384(),

            Algorithm::HS512 => MessageDigest::sha512(),
            Algorithm::RS512 => MessageDigest::sha512(),
            Algorithm::ES512 => MessageDigest::sha512(),
        }
    }
}

impl ToString for Algorithm {
    fn to_string(&self) -> String {
        match *self {
            Algorithm::HS256 => "HS256",
            Algorithm::HS384 => "HS384",
            Algorithm::HS512 => "HS512",
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            Algorithm::ES512 => "ES512",
        }.to_string()
    }
}
