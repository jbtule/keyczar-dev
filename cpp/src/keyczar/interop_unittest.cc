// Copyright 2013 Jay Tuley All Rights reserved.
//
// Author: Jay Tuley (jay+code@tuley.name)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <keyczar/base/scoped_ptr.h>
#include <keyczar/interop_test.h>
#include <testing/gtest/include/gtest/gtest.h>

namespace keyczar {

INSTANTIATE_TEST_CASE_P(InteropLanguages,
                       InteropTest,
                       testing::Values("cs", "go", "j", "py", "py3"));

TEST_P(InteropTest, DecryptPrimaryAes) {
  TestDecrypt("aes", "2");
}

TEST_P(InteropTest, DecryptActiveAes) {
  TestDecrypt("aes", "1");
}

TEST_P(InteropTest, DecryptAes128) {
  TestDecrypt("aes-size", "128");
}

TEST_P(InteropTest, DecryptAes192) {
  TestDecrypt("aes-size", "192");
}

TEST_P(InteropTest, DecryptAes256) {
  TestDecrypt("aes-size", "256");
}

TEST_P(InteropTest, DecryptPrimaryCryptedAes) {
  TestDecryptWithCrypter("aes-crypted", "aes", "2");
}

TEST_P(InteropTest, DecryptActiveCryptedAes) {
  TestDecryptWithCrypter("aes-crypted", "aes", "1");
}

TEST_P(InteropTest, DecryptPrimaryRSA) {
  TestDecrypt("rsa", "2");
}

TEST_P(InteropTest, DecryptActiveRSA) {
  TestDecrypt("rsa", "1");
}

TEST_P(InteropTest, DecryptRsa1024) {
  TestDecrypt("rsa-size", "1024");
}

TEST_P(InteropTest, DecryptRsa2048) {
  TestDecrypt("rsa-size", "2048");
}

TEST_P(InteropTest, DecryptRsa4096) {
  TestDecrypt("rsa-size", "4096");
}

TEST_P(InteropTest, SignedSessionDecryptRsa) {
  TestSignedSessionDecrypt("rsa", "dsa", "2");
}

TEST_P(InteropTest, VerifyPrimaryHmac) {
  TestVerify("hmac", "hmac", "2");
}

TEST_P(InteropTest, VerifyActiveHmac) {
  TestVerify("hmac", "hmac", "1");
}

TEST_P(InteropTest, VerifyAttachedHmac) {
  TestAttachedVerify("hmac", "hmac", "", "2");
}

TEST_P(InteropTest, VerifyAttachedSecretHmac) {
  TestAttachedVerify("hmac", "hmac", "secret", "2");
}

TEST_P(InteropTest, VerifyUnversionedHmac) {
  TestVerifyUnversioned("hmac", "hmac", "2");
}

TEST_P(InteropTest, VerifyPrimaryDsa) {
  TestVerify("dsa", "dsa", "2");
}

TEST_P(InteropTest, VerifyActiveDsa) {
  TestVerify("dsa", "dsa", "1");
}

TEST_P(InteropTest, VerifyPrimaryPublicDsa) {
  TestVerify("dsa", "dsa.public", "2");
}

TEST_P(InteropTest, VerifyActivePublicDsa) {
  TestVerify("dsa", "dsa.public", "1");
}

TEST_P(InteropTest, VerifyAttachedDsa) {
  TestAttachedVerify("dsa", "dsa", "", "2");
}

TEST_P(InteropTest, VerifyAttachedSecretDsa) {
  TestAttachedVerify("dsa", "dsa", "secret", "2");
}

TEST_P(InteropTest, VerifyAttachedPublicDsa) {
  TestAttachedVerify("dsa", "dsa.public", "", "2");
}

TEST_P(InteropTest, VerifyAttachedSecretPublicDsa) {
  TestAttachedVerify("dsa", "dsa.public", "secret", "2");
}

TEST_P(InteropTest, VerifyUnversionedDsa) {
  TestVerifyUnversioned("dsa", "dsa", "2");
}

TEST_P(InteropTest, VerifyUnversionedPublicDsa) {
  TestVerifyUnversioned("dsa", "dsa.public", "2");
}

TEST_P(InteropTest, VerifyPrimaryRsa) {
  TestVerify("rsa-sign", "rsa-sign", "2");
}

TEST_P(InteropTest, VerifyActiveRsa) {
  TestVerify("rsa-sign", "rsa-sign", "1");
}

TEST_P(InteropTest, VerifyPrimaryPublicRsa) {
  TestVerify("rsa-sign", "rsa-sign.public", "2");
}

TEST_P(InteropTest, VerifyActivePublicRsa) {
  TestVerify("rsa-sign", "rsa-sign.public", "1");
}

TEST_P(InteropTest, VerifyRsa1024) {
  TestVerify("rsa-sign-size", "rsa-sign-size", "1024");
}

TEST_P(InteropTest, VerifyRsa2048) {
  TestVerify("rsa-sign-size", "rsa-sign-size", "2048");
}

TEST_P(InteropTest, VerifyRsa4096) {
  TestVerify("rsa-sign-size", "rsa-sign-size", "4096");
}

TEST_P(InteropTest, VerifyPublicRsa1024) {
  TestVerify("rsa-sign-size", "rsa-sign-size.public", "1024");
}

TEST_P(InteropTest, VerifyPublicRsa2048) {
  TestVerify("rsa-sign-size", "rsa-sign-size.public", "2048");
}

TEST_P(InteropTest, VerifyPublicRsa4096) {
  TestVerify("rsa-sign-size", "rsa-sign-size.public", "4096");
}

TEST_P(InteropTest, VerifyAttachedRsa) {
  TestAttachedVerify("rsa-sign", "rsa-sign", "", "2");
}

TEST_P(InteropTest, VerifyAttachedSecretRsa) {
  TestAttachedVerify("rsa-sign", "rsa-sign", "secret", "2");
}

TEST_P(InteropTest, VerifyAttachedPublicRsa) {
  TestAttachedVerify("rsa-sign", "rsa-sign.public", "", "2");
}

TEST_P(InteropTest, VerifyAttachedSecretPublicRsa) {
  TestAttachedVerify("rsa-sign", "rsa-sign.public", "secret", "2");
}

TEST_P(InteropTest, VerifyUnversionedRsa) {
  TestVerifyUnversioned("rsa-sign", "rsa-sign", "2");
}

TEST_P(InteropTest, VerifyUnversionedPublicRsa) {
  TestVerifyUnversioned("rsa-sign", "rsa-sign.public", "2");
}

}  // namespace keyczar
