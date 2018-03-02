// Copyright 2018 LightDiscord
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! Collection of Jwt Errors.

#![allow(missing_docs)]
error_chain!{
    foreign_links {
        Io(::std::io::Error);
        Serde(::serde_json::Error);
        //OpenSsl(::openssl::error::ErrorStack);
        Base64(::base64::DecodeError);
        //Time(::std::time::SystemTimeError);
    }

    errors {
        InvalidAlgorithm {
            description("invalid algorithm"),
            display("invalid algorithm")
        }

        MissingAlgorithm {
            description("missing algorithm"),
            display("can't find algo used by the jwt")
        }

        InvalidJwt {
            description("invalid jwt"),
            display("invalid jwt")
        }

        InvalidSignature {
            description("invalid signature"),
            display("invalid signautre")
        }

        VerificationFailed (fail: String) {
            description("verification step failed"),
            display("verification step failed: '{}'", fail)
        }
    }
}
