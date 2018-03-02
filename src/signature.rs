// Copyright 2018 LightDiscord
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! Sign or verify a signature

use ::error::{ Result };

/// Transform something into a secret, a public or private key
pub trait AsKey {
    /// Convert it!
    fn as_key(&self) -> Result<Vec<u8>>;
}

impl AsKey for ::std::path::PathBuf {
    fn as_key(&self) -> Result<Vec<u8>> {
        use std::io::Read;

        let mut file = ::std::fs::File::open(self)?;
        let mut buffer: Vec<u8> = Vec::new();
        file.read_to_end(&mut buffer)?;

        Ok(buffer)
    }
}

impl AsKey for String {
    fn as_key(&self) -> Result<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }
}



/*
use std::fs::File;
use std::path::PathBuf;
use std::io::Read;
use std::convert::Into;
use std::fmt;
use std::borrow::Cow;

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::ec::EcKey;

use base64;

use ::{ Result };
use ::algorithm::Algorithm;

/// Transform something into a key.
pub trait AsKey {
    /// Function that will turn it into a key
    fn as_key(&self) -> Result<Vec<u8>>;
}

impl AsKey for PathBuf {
    fn as_key(&self) -> Result<Vec<u8>> {
        let mut file = File::open(self)?;
        let mut buffer: Vec<u8> = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }
}

impl AsKey for String {
    fn as_key(&self) -> Result<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }
}

/// Signature operations
#[derive(Debug, Clone)]
pub struct Signature<'signature>(pub Cow<'signature, str>, pub Algorithm);

impl<'signature> fmt::Display for Signature<'signature> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'signature> Signature<'signature> {
    pub fn new<S>(raw: S, algorithm: Algorithm) -> Self where S: Into<Cow<'signature, str>> {
        Signature(raw.into(), algorithm)
    }

    /// Sign a jwt using HMAC
    pub fn hmac<P: AsKey>(data: &str, key_path: &P, algorithm: Algorithm) -> Result<Self> {
        let digest: MessageDigest = algorithm.into();

        let key = PKey::hmac(&key_path.as_key()?)?;
        let mut signer = Signer::new(digest, &key)?;
        let _ = signer.update(data.as_bytes())?;
        let signature = signer.sign_to_vec()?;
        let signature = base64::encode_config(signature.as_slice(), base64::URL_SAFE);

        Ok(Signature::new(signature, algorithm))
    }

    /// Sign a jwt using RSA
    pub fn rsa<P: AsKey>(data: &str, private_key_path: &P, algorithm: Algorithm ) -> Result<Self> {
        let digest: MessageDigest = algorithm.into();

        let key = Rsa::private_key_from_pem(&private_key_path.as_key()?)?;
        let key = PKey::from_rsa(key)?;

        let mut signer = Signer::new(digest, &key)?;
        signer.update(data.as_bytes())?;

        let signature = signer.sign_to_vec()?;
        let signature = base64::encode_config(signature.as_slice(), base64::URL_SAFE);

        Ok(Signature::new(signature, algorithm))
    }

    /// Sign a jwt using ECDSA
    pub fn es<P: AsKey>(data: &str, private_key_path: &P, algorithm: Algorithm) -> Result<Self> {
        let digest: MessageDigest = algorithm.into();

        let key = EcKey::private_key_from_pem(&private_key_path.as_key()?)?;
        let key = PKey::from_ec_key(key)?;

        let mut signer = Signer::new(digest, &key)?;
        signer.update(data.as_bytes())?;

        let signature = signer.sign_to_vec()?;
        let signature = base64::encode_config(signature.as_slice(), base64::URL_SAFE);

        Ok(Signature::new(signature, algorithm))
    }

    /// Verify if a signature is valid
    pub fn verify<P: AsKey>(&self, data: String, key: &P) -> Result<bool> {
        let &Signature(ref signature, algorithm) = self;
        let signature = signature.clone().into_owned();
        let signature = &base64::decode_config(&signature, base64::URL_SAFE)?;

        match algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                let digest: MessageDigest = algorithm.into();

                let key = &key.as_key()?;
                let key = PKey::hmac(key)?;
                let mut signer = Signer::new(digest, &key)?;
                signer.update(data.as_bytes())?;
                let other_signature = signer.sign_to_vec()?;

                let result = compare(signature, &other_signature);
                Ok(result)
            },

            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                let key = Rsa::public_key_from_pem(&key.as_key()?)?;
                let key = PKey::from_rsa(key)?;

                let digest: MessageDigest = algorithm.into();
                let mut verifier = Verifier::new(digest, &key)?;
                verifier.update(data.as_bytes())?;
                Ok(verifier.verify(signature)?)
            }

            Algorithm::ES256 | Algorithm::ES384 | Algorithm::ES512 => {
                let key = PKey::public_key_from_pem(&key.as_key()?)?;

                let digest: MessageDigest = algorithm.into();
                let mut verifier = Verifier::new(digest, &key)?;
                verifier.update(data.as_bytes())?;
                Ok(verifier.verify(signature)?)
            }
        }
    }
}

fn compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut res: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        res |= x ^ y;
    }

    res == 0
}

#[cfg(test)]
mod tests {
    use super::compare;

    #[test]
    fn test_compare_same () {
        let first = "The same!".as_bytes();
        let second = "The same!".as_bytes();
        let result = compare(first, second);

        assert!(result);
    }

    #[test]
    fn test_compare_different () {
        let first = "The same!".as_bytes();
        let second = "Not the same!".as_bytes();
        let result = compare(first, second);

        assert!(!result);
    }
}
*/
