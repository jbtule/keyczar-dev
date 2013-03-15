// Copyright 2009 Sebastien Martini (seb@dbzteam.org)
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
#include <string>

#include <testing/gtest/include/gtest/gtest.h>

#include <keyczar/base/base64w.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/ref_counted.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/values.h>
#include <keyczar/key_type.h>
#include <keyczar/keyczar_test.h>
#include <keyczar/openssl/rsa.h>
#include <keyczar/rsa_private_key.h>
#include <keyczar/rsa_public_key.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_file_writer.h>

namespace keyczar {

class SpecialTest : public KeyczarTest {
 protected:

  // Loads private key from JSON file.
  scoped_refptr<RSAPrivateKey> LoadRSAPrivateKey(const FilePath& path,
                                                 int key_version) {
    rw::KeysetJSONFileReader reader(path);
    scoped_ptr<Value> value(reader.ReadKey(key_version));
    EXPECT_NE(static_cast<Value*>(NULL), value.get());
    scoped_refptr<RSAPrivateKey> private_key(
        RSAPrivateKey::CreateFromValue(*value));
    CHECK(private_key);
    return private_key;
  }

};

TEST_F(SpecialTest, TolerateStringsAsInts) {
  const FilePath tolerate_path = data_path_.Append("tolerate-strings");
  scoped_refptr<RSAPrivateKey> private_key = LoadRSAPrivateKey(tolerate_path, 1);

  // Try to decrypt corresponding data file
  std::string b64w_encrypted_data;
  EXPECT_TRUE(base::ReadFileToString(tolerate_path.Append("1.out"),
                                     &b64w_encrypted_data));
  std::string encrypted_data;
  EXPECT_TRUE(base::Base64WDecode(b64w_encrypted_data, &encrypted_data));
  std::string decrypted_data;
  EXPECT_TRUE(private_key->Decrypt(encrypted_data, &decrypted_data));

  // Compares clear texts
  EXPECT_EQ(decrypted_data, input_data_);
}








}  // namespace keyczar