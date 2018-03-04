// Copyright 2018 LightDiscord
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! Sign or verify a signature

#![allow(unused_variables)]

use ::error;
use ::Signature;
use ::algorithm::Algorithm;

use std::io::Read;

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::{Signer, Verifier};
use openssl::ec::EcKey;
use openssl::rsa::Rsa;

use base64;

/// Transform something into a secret, a public or private key
pub trait AsKey {
    /// Convert it!
    fn as_key(&self) -> error::Result<Vec<u8>>;
}

impl AsKey for ::std::path::PathBuf {
    fn as_key(&self) -> error::Result<Vec<u8>> {
        let mut file = ::std::fs::File::open(self)?;
        let mut buffer: Vec<u8> = Vec::new();
        file.read_to_end(&mut buffer)?;

        Ok(buffer)
    }
}

impl AsKey for String {
    fn as_key(&self) -> error::Result<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }
}

/// HMAC Algorithm
pub struct HMAC;

/// RSA Algorithm
pub struct RSA;

/// ECDSA Algorithm
pub struct ECDSA;

/// Signature with an algorithm bound to it
#[derive(Debug)]
pub struct BindSignature<'s> (pub Signature<'s>, pub Algorithm);

/// Sign something and verify signature
pub trait Sign {
    /// Error Result
    type Error;

    /// Sign something
    fn sign<'data, K: AsKey>(data: &'data str, key: &K, algorithm: Algorithm) -> Result<BindSignature<'data>, Self::Error>;

    /// Verify signature
    fn verify<K: AsKey>(signature: BindSignature, data: &str, key: &K) -> Result<bool, Self::Error>;
}

impl Sign for HMAC {
    type Error = error::Error;

    fn sign<'data, K: AsKey>(data: &'data str, key: &K, algorithm: Algorithm) -> error::Result<BindSignature<'data>> {
        let digest: MessageDigest = algorithm.into();

        let key = PKey::hmac(&key.as_key()?)?;
        let mut signer = Signer::new(digest, &key)?;
        let _ = signer.update(data.as_bytes())?;

        let signature = signer.sign_to_vec()?;
        let signature = base64::encode_config(signature.as_slice(), base64::URL_SAFE);
        let signature = BindSignature(Signature::new(signature), algorithm);

        Ok(signature)
    }

    fn verify<K: AsKey>(signature: BindSignature, data: &str, key: &K) -> error::Result<bool> {
        let BindSignature(signature, algorithm) = signature;
        let Signature(signature) = signature;
        let signature = signature.into_owned();
        let signature = base64::decode_config(&signature, base64::URL_SAFE)?;

        let digest: MessageDigest = algorithm.into();

        let key = &key.as_key()?;
        let key = PKey::hmac(key)?;
        let mut signer = Signer::new(digest, &key)?;
        signer.update(data.as_bytes())?;
        let other_signature = signer.sign_to_vec()?;

        Ok(signature == other_signature)
    }
}

impl Sign for RSA {
    type Error = error::Error;

    fn sign<'data, K: AsKey>(data: &'data str, key: &K, algorithm: Algorithm) -> error::Result<BindSignature<'data>> {
        let digest: MessageDigest = algorithm.into();

        let key = Rsa::private_key_from_pem(&key.as_key()?)?;
        let key = PKey::from_rsa(key)?;
        let mut signer = Signer::new(digest, &key)?;
        let _ = signer.update(data.as_bytes())?;

        let signature = signer.sign_to_vec()?;
        let signature = base64::encode_config(signature.as_slice(), base64::URL_SAFE);
        let signature = BindSignature(Signature::new(signature), algorithm);

        Ok(signature)
    }

    fn verify<K: AsKey>(signature: BindSignature, data: &str, key: &K) -> error::Result<bool> {
        let BindSignature(signature, algorithm) = signature;
        let Signature(signature) = signature;
        let signature = signature.into_owned();
        let signature = base64::decode_config(&signature, base64::URL_SAFE)?;

        let key = Rsa::public_key_from_pem(&key.as_key()?)?;
        let key = PKey::from_rsa(key)?;
        let digest: MessageDigest = algorithm.into();
        let mut verifier = Verifier::new(digest, &key)?;
        let _ = verifier.update(data.as_bytes())?;

        Ok(verifier.verify(&signature)?)
    }
}

impl Sign for ECDSA {
    type Error = error::Error;

    fn sign<'data, K: AsKey>(data: &'data str, key: &K, algorithm: Algorithm) -> error::Result<BindSignature<'data>> {
        let digest: MessageDigest = algorithm.into();

        let key = EcKey::private_key_from_pem(&key.as_key()?)?;
        let key = PKey::from_ec_key(key)?;
        let mut signer = Signer::new(digest, &key)?;
        let _ = signer.update(data.as_bytes())?;

        let signature = signer.sign_to_vec()?;
        let signature = base64::encode_config(signature.as_slice(), base64::URL_SAFE);
        let signature = BindSignature(Signature::new(signature), algorithm);

        Ok(signature)
    }

    fn verify<K: AsKey>(signature: BindSignature, data: &str, key: &K) -> error::Result<bool> {
        let BindSignature(signature, algorithm) = signature;
        let Signature(signature) = signature;
        let signature = signature.into_owned();
        let signature = base64::decode_config(&signature, base64::URL_SAFE)?;

        let key = PKey::public_key_from_pem(&key.as_key()?)?;
        let digest: MessageDigest = algorithm.into();
        let mut verifier = Verifier::new(digest, &key)?;
        let _ = verifier.update(data.as_bytes())?;

        Ok(verifier.verify(&signature)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::env;

    #[test]
    fn test_hmac() {
        let secret = "This is super mega secret!".to_string();
        let header_and_body = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJGQkkhIGN1eicgaXQncyBzZWNyZXQhIHNodXQhIiwiZXhwIjoxNTE5OTk0NTAxLCJoZWxsbyI6IndvcmxkIiwiaWF0IjoxNTE5OTk0NDkxLCJpc3MiOiJUZXN0LW1hbiEiLCJsaWdodCI6ImRpc2NvcmQifQ==";
        let signature = HMAC::sign(header_and_body, &secret, Algorithm::HS256).unwrap();

        assert_eq!(signature.0, Signature::new("gS76BWOStsnrG9nMacQQE7ThHM1UIR2omB6YkBaQjZ0="));
        assert!(HMAC::verify(signature, header_and_body, &secret).unwrap());
    }

    #[test]
    fn test_rsa() {
        let secret = rsa_private_key();
        let header_and_body = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJGQkkhIGN1eicgaXQncyBzZWNyZXQhIHNodXQhIiwiZXhwIjoxNTE5OTk0NTAxLCJoZWxsbyI6IndvcmxkIiwiaWF0IjoxNTE5OTk0NDkxLCJpc3MiOiJUZXN0LW1hbiEiLCJsaWdodCI6ImRpc2NvcmQifQ==";
        let signature = RSA::sign(header_and_body, &secret, Algorithm::RS256).unwrap();

        assert_eq!(signature.0, Signature::new("T_kaMgUEwSPbIab0VBvxC-4YmW_9MpTJiNDxFoZbs9TZPBMCggYW1FEmU3aI6B6Fs-eJPu-pkGz2VEbq6J7LLLF57ALxZKHxhdev1oa2Oik2lkVtbN7-KWgW0uTgaWRpmeOE4TPO4g8T5i3k9J-iaDResM_LswPLTwr92BychsapNl6SRRdSrDo_XJWOgXvS72Zw-1ZsjgJJMpVIF1ygD9m50ICiWyB6lVU-McvaSRWo3UBmipz-C6ApZMBQj1m6In89y-hEL-XpQ0flwBIMLyDHc7YmyWUiEXkHPAZ0tDD5wHBRk6N74o7cdjWeBh2ZFfvdWztjL1u8TYV3RBbSag=="));

        let secret = rsa_public_key();
        assert!(RSA::verify(signature, header_and_body, &secret).unwrap());
    }

    #[test]
    fn test_ecdsa() {
        let secret = ecdsa_private_key();
        let header_and_body = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJGQkkhIGN1eicgaXQncyBzZWNyZXQhIHNodXQhIiwiZXhwIjoxNTE5OTk0NTAxLCJoZWxsbyI6IndvcmxkIiwiaWF0IjoxNTE5OTk0NDkxLCJpc3MiOiJUZXN0LW1hbiEiLCJsaWdodCI6ImRpc2NvcmQifQ==";
        let signature = ECDSA::sign(header_and_body, &secret, Algorithm::ES256).unwrap();

        let secret = ecdsa_public_key();
        assert!(ECDSA::verify(signature, header_and_body, &secret).unwrap());
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

    fn ecdsa_public_key () -> PathBuf {
        let mut base_path = env::current_dir().unwrap();
        base_path.push("resources");
        base_path.push("ecdsa.pub");

        base_path
    }

    fn ecdsa_private_key () -> PathBuf {
        let mut base_path = env::current_dir().unwrap();
        base_path.push("resources");
        base_path.push("ecdsa.private.key");

        base_path
    }
}
