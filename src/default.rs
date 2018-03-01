// Copyright 2018 LightDiscord
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! Registered Claim Names

use std::convert::Into;
use serde_json::Value;

/// Different Registered Claims
#[derive(Debug, Clone, PartialEq)]
pub enum RegisteredClaims {
    /// "iss" (Issuer) Claim
    Issuer(String),

    /// "sub" (Subject) Claim
    Subject(String),

    /// "aud" (Audience) Claim
    Audience(String),

    /// "exp" (Expiration Time) Claim
    ExpirationTime(u64),

    /// "nbf" (Not Before) Claim
    NotBefore(u64),

    /// "iat" (Issued At) Claim
    IssuedAt(u64),

    /// "jti" (JWT ID) Claim
    JwtId(String)
}

impl Into<Value> for RegisteredClaims {
    fn into (self) -> Value {
        match self {
            RegisteredClaims::Issuer(iss) => json!(iss),
            RegisteredClaims::Subject(sub) => json!(sub),
            RegisteredClaims::Audience(aud) => json!(aud),
            RegisteredClaims::ExpirationTime(exp) => json!(exp),
            RegisteredClaims::NotBefore(nbf) => json!(nbf),
            RegisteredClaims::IssuedAt(iat) => json!(iat),
            RegisteredClaims::JwtId(jti) => json!(jti),
        }
    }
}

impl ToString for RegisteredClaims {
    fn to_string (&self) -> String {
        match *self {
            RegisteredClaims::Issuer(_) => "iss",
            RegisteredClaims::Subject(_) => "sub",
            RegisteredClaims::Audience(_) => "aud",
            RegisteredClaims::ExpirationTime(_) => "exp",
            RegisteredClaims::NotBefore(_) => "nbf",
            RegisteredClaims::IssuedAt(_) => "iat",
            RegisteredClaims::JwtId(_) => "jti",
        }.to_string()
    }
}
