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

#ifndef KEYCZAR_INTEROP_TEST_H_
#define KEYCZAR_INTEROP_TEST_H_

#include <string>

#include <testing/gtest/include/gtest/gtest.h>

#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/logging.h>
#include <keyczar/base_test/path_service.h>

namespace keyczar {

class InteropTest : public ::testing::TestWithParam<std::string> {
  protected:
    virtual void SetUp() {
      base_test::PathService::Get(base_test::DIR_SOURCE_ROOT, &data_path_);
      data_path_ = data_path_.Append("keyczar");
      data_path_ = data_path_.Append("test-data");
      data_path_ = data_path_.Append("interop-data");

      input_data_ = "This is some test data";
  }

  virtual void TearDown() {
  }

  FilePath data_path_;
  std::string input_data_;

  std::string LangDir() const;

  void TestVerify(
                  const std::string& sig_data,
                  const std::string& verify_key,
                  const std::string& filename) const;

  void TestAttachedVerify(
                          const std::string& sig_data,
                          const std::string& verify_key,
                          const std::string& hidden_value,
                          const std::string& filename) const;

  void TestVerifyUnversioned(
                             const std::string& sig_data,
                             const std::string& verify_key,
                             const std::string& filename) const;

  void TestDecrypt(
                   const std::string& decrypt_key,
                   const std::string&  filename) const;

  void TestDecryptWithCrypter(
                              const std::string& decrypt_key,
                              const std::string& crypter_key,
                              const std::string& filename) const;


  void TestSignedSessionDecrypt(
                                const std::string& decrypt_key,
                                const std::string& verify_key,
                                const std::string& filename) const;

  void ReadDataFile(const std::string& dir,
                    const std::string& filename, 
                    std::string* content) const;
};

}  // namespace keyczar

#endif  // KEYCZAR_INTEROP_TEST_H_
