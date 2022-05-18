//
// Created by dawid on 5/17/22.
//

#include <my_utils/Time.h>

#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eax.h>

#include "include/Crypto.h"

std::string crypto::UUID() {
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);

    using namespace mutl::time;
    unsigned long long timestamp = now<nanoseconds>();

    return sha256Hash(std::to_string(timestamp));
}

std::string crypto::sha256Hash(const std::string &aString) {
    std::string digest;
    CryptoPP::SHA256 hash;

    CryptoPP::StringSource foo(
            aString,
            true,
            new CryptoPP::HashFilter(
                    hash,
                    new CryptoPP::Base64Encoder(
                            new CryptoPP::StringSink(digest))));
    digest.pop_back();
    return digest;
}

/// encrypt string and generate random iv (remember to save the iv_out somewhere)
std::string crypto::encrypt(const std::string &str, std::string &iv_out, const std::string &key_) {
    using namespace CryptoPP;

    AutoSeededRandomPool prng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    key.Assign((unsigned char *) key_.c_str(), key_.size());
    prng.GenerateBlock(iv, iv.size());

    iv_out = std::string(iv.begin(), iv.end());

    EAX<AES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    std::string cipher;
    StringSource ss(str, true,
                    new AuthenticatedEncryptionFilter(e,
                                                      new StringSink(cipher)
                    ) // AuthenticatedEncryptionFilter
    ); // StringSource

    return cipher;
}

std::string crypto::decrypt(const std::string &cipher, const std::string &iv_str, const std::string &key_) {
    using namespace CryptoPP;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    key.Assign((unsigned char *) key_.c_str(), key_.size());
    iv.Assign((unsigned char *) iv_str.c_str(), iv_str.size());

    std::string recovered;
    EAX<AES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);
    StringSource ss(cipher, true,
                    new AuthenticatedDecryptionFilter(d,
                                                      new StringSink(recovered)
                    ) // AuthenticatedDecryptionFilter
    ); // StringSource

    return recovered;
}