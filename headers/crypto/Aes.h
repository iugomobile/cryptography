#pragma once

/**
 * CONFIDENTIAL
 *
 *  2003 IUGO Mobile Entertainment Inc
 *  All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains the property of
 * IUGO Mobile Entertainment Inc.  The intellectual and technical concepts
 * contained herein are proprietary to IUGO Mobile Entertainment Inc. and
 * may be covered by U.S. and Foreign Patents, patents in process, and are
 * protected by trade secret or copyright law.  Dissemination of this
 * information or reproduction of this material is strictly forbidden unless
 * prior written permission is obtained from IUGO Mobile Entertainment Inc.
 */

#include "igl/crypto/Defs.h"


namespace iugo::crypto
{
#pragma mark - AesCipher
  struct AesCipher
  {
    /// Forward S-box
    static Array<uint8, 256> const FSb;
    /// Forward tables
    static Array<uint, 256> const FT0;
    static Array<uint, 256> const FT1;
    static Array<uint, 256> const FT2;
    static Array<uint, 256> const FT3;

    /// Reverse S-box
    static Array<uint8, 256> const RSb;
    /// Reverse tables
    static Array<uint, 256> const RT0;
    static Array<uint, 256> const RT1;
    static Array<uint, 256> const RT2;
    static Array<uint, 256> const RT3;
  };
  
  
#pragma mark - AesEncipher
  namespace details
  {
    struct AesEncipher: AesCipher
    {
      using VectorType = Array<uint, 4, 16>;
      
      Array<uint, 64, 16> Matrix;
      
      AesEncipher(uint roundCount, ListRef<uint const> key) noexcept;
      
      VectorType Transform(uint roundCount, VectorType vector) const noexcept;
    };
  }

  template<uint RoundCount>
  struct AesEncipher: details::AesEncipher
  {
    using KeyType = Array<uint, 4 + RoundCount - 10, 16>;
    
    AesEncipher(KeyType const& key) noexcept
    : details::AesEncipher{RoundCount, key}
    {
    }
    
    VectorType Transform(VectorType vector) const noexcept
    {
      return details::AesEncipher::Transform(RoundCount, vector);
    }
  };
  
  using EcbAes128Encipher = Ecb<AesEncipher<10>>;
  using EcbAes256Encipher = Ecb<AesEncipher<14>>;
  
  
#pragma mark - AesDecipher
  namespace details
  {
    struct AesDecipher: AesCipher
    {
      using VectorType = Array<uint, 4, 16>;
      
      Array<uint, 64, 16> Matrix;
      
      AesDecipher(uint roundCount, AesEncipher const& key) noexcept;
      
      VectorType Transform(uint roundCount, VectorType vector) const noexcept;
    };
  }
  
  template<uint RoundCount>
  struct AesDecipher: details::AesDecipher
  {
    using KeyType = AesEncipher<RoundCount>;
    
    AesDecipher(KeyType const& key) noexcept
    : details::AesDecipher{RoundCount, key}
    {
    }
    
    VectorType Transform(VectorType vector) const noexcept
    {
      return details::AesDecipher::Transform(RoundCount, vector);
    }
  };
  
  using EcbAes128Decipher = Ecb<AesDecipher<10>>;
  using EcbAes256Decipher = Ecb<AesDecipher<14>>;
}
