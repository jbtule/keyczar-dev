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

#include <fstream>

#include <keyczar/base/scoped_ptr.h>
#include <keyczar/keyczar.h>
#include <keyczar/interop_test.h>
#include <keyczar/rw/keyset_encrypted_file_reader.h>
#include <keyczar/session.h>

namespace keyczar {


std::string InteropTest::LangDir() const {
    return GetParam() + "_data";
}


void InteropTest::TestVerify(
                       const std::string& sig_data,
                       const std::string& verify_key,
                       const std::string& filename) const {
  std::string signature;
  const FilePath verify_path = data_path_.Append(LangDir()).Append(sig_data);

  ReadDataFile(sig_data, filename + ".out" , &signature);

  scoped_ptr<Verifier> verifier(Verifier::Read(verify_path.value()));
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->Verify(input_data_, signature));
}

void InteropTest::TestAttachedVerify(
                          const std::string& sig_data,
                          const std::string& verify_key,
                          const std::string& hidden_value,
                          const std::string& filename) const {
  std::string signature;
  const FilePath verify_path = data_path_.Append(LangDir()).Append(sig_data);
  std::string full_filename = filename;
  if (hidden_value != "") {
    full_filename += ".";
  }
  full_filename += hidden_value;

  ReadDataFile(sig_data, full_filename + ".attached", &signature);

  scoped_ptr<Verifier> verifier(Verifier::Read(verify_path.value()));
  std::string signed_data;
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->AttachedVerify(signature, hidden_value, &signed_data));
  EXPECT_EQ(input_data_, signed_data);
}

void InteropTest::TestVerifyUnversioned(
                             const std::string& sig_data,
                             const std::string& verify_key,
                             const std::string& filename) const {
  std::string signature;
  const FilePath verify_path = data_path_.Append(LangDir()).Append(sig_data);

  ReadDataFile(sig_data, filename + ".unversioned", &signature);

  scoped_ptr<UnversionedVerifier> verifier(
    UnversionedVerifier::Read(verify_path.value()));
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->Verify(input_data_, signature));
}

void InteropTest::TestDecrypt(
                        const std::string& decrypt_key,
                        const std::string&  filename) const {
  FilePath keyset_path = data_path_.Append(LangDir()).Append(decrypt_key);
  scoped_ptr<Crypter> crypter(Crypter::Read(keyset_path.value()));

  // Try to decrypt corresponding data file
  std::string b64w_encrypted_data;

  ReadDataFile(decrypt_key, filename + ".out", &b64w_encrypted_data);

  std::string decrypted_data;
  EXPECT_TRUE(crypter->Decrypt(b64w_encrypted_data, &decrypted_data));

  // Compares clear texts
  EXPECT_EQ(decrypted_data, input_data_);
}

void InteropTest::TestDecryptWithCrypter(
                              const std::string& decrypt_key,
                              const std::string& crypter_key,
                              const std::string& filename) const {
  const FilePath aes_path = data_path_.Append(LangDir()).Append(crypter_key);
  scoped_ptr<Crypter> decrypter(Crypter::Read(aes_path.value()));
  ASSERT_TRUE(decrypter.get());

  const FilePath aes_crypted_path = data_path_.Append(LangDir())
      .Append(decrypt_key);
  rw::KeysetEncryptedJSONFileReader encrypted_reader(aes_crypted_path.value(),
                                                     decrypter.release());

  scoped_ptr<Crypter> crypter(Crypter::Read(encrypted_reader));
  std::string b64w_encrypted_data;
  ReadDataFile(decrypt_key, filename + ".out", &b64w_encrypted_data);

  std::string decrypted_data;
  EXPECT_TRUE(crypter->Decrypt(b64w_encrypted_data, &decrypted_data));

  // Compares clear texts
  EXPECT_EQ(decrypted_data, input_data_);
}

void InteropTest::TestSignedSessionDecrypt(const std::string& decrypt_key,
                                const std::string& verify_key,
                                const std::string& filename) const {
  FilePath decrypt_path = data_path_.Append(LangDir()).Append(decrypt_key);
  FilePath verify_path = data_path_.Append(LangDir()).Append(verify_key);

  std::string session_material;
  std::string ciphertext;
  std::string plaintext;
  ReadDataFile(decrypt_key, filename + ".signedsession.material",
               &session_material);
  ReadDataFile(decrypt_key, filename + ".signedsession.ciphertext",
               &ciphertext);

  scoped_ptr<SignedSessionDecrypter> decrypter(
      SignedSessionDecrypter::NewSessionDecrypter(
        Crypter::Read(decrypt_path), Verifier::Read(verify_path),
          session_material));

  ASSERT_TRUE(decrypter.get());

  EXPECT_TRUE(decrypter->SessionDecrypt(ciphertext, &plaintext));

  // Compares clear texts
  EXPECT_EQ(plaintext, input_data_);
}


void InteropTest::ReadDataFile(const std::string& dir,
                               const std::string& filename,
                               std::string* content) const {
  ASSERT_TRUE(content != NULL);

  const FilePath path = data_path_.Append(LangDir())
      .Append(dir).Append(filename);
  std::ifstream input_file(path.value().c_str());
  ASSERT_TRUE(input_file);

  input_file >> *content;
  ASSERT_GT(content->size(), 0);
}

}  // namespace keyczar
