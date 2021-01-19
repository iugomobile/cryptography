/**
 *  2003 IUGO Mobile Entertainment Inc
 *  All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains the property of
 * IUGO Mobile Entertainment Inc.  The intellectual and technical concepts
 * contained herein are proprietary to IUGO Mobile Entertainment Inc. and
 * may be covered by U.S. and Foreign Patents, patents in process, and are
 * protected by trade secret or copyright law.
 */

#include "igl/crypto/Defs.h"

#include "igl/crypto/Aes.h"


namespace iugo::crypto
{
#if IGL_AES_DEFAULT == 256
  constexpr Array<uint, 8, 16> SecretKey = {0x23379363, 0x8cb85ff0, 0xfe61930b, 0xe3e19c9a, 0xe11ae2a6, 0x762f2208, 0x0c034ed9, 0xe0082e81};
#else
  constexpr Array<uint, 4, 16> SecretKey = {0x23379363, 0xfe61930b, 0xe11ae2a6, 0x0c034ed9};
#endif
}
  
  
namespace iugo
{
  std::size_t ciphertext_size(std::size_t size) noexcept
  {
#if IGL_AES_DEFAULT == 256
    return ceil2(size + 1, sizeof(crypto::EcbAes256Encipher::BlockType));
#else
    return ceil2(size + 1, sizeof(crypto::EcbAes128Encipher::BlockType));
#endif
  }
  
  List<byte> encrypt(ListRef<byte const> data)
  {
#if IGL_AES_DEFAULT == 256
    return crypto::EcbAes256Encipher{crypto::SecretKey, data}.Text();
#else
    return crypto::EcbAes128Encipher{crypto::SecretKey, data}.Text();
#endif
  }
  
  List<byte> decrypt(ListRef<byte const> data)
  {
#if IGL_AES_DEFAULT == 256
    return crypto::EcbAes256Decipher{crypto::SecretKey, data}.Text();
#else
    return crypto::EcbAes128Decipher{crypto::SecretKey, data}.Text();
#endif
  }
}
