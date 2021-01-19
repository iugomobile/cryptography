#pragma once

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


namespace iugo::crypto
{
#pragma mark - Sha256Hash
  using Sha256Hash = Array<byte, 32, 16>;
  
  
#pragma mark - Sha256Encipher
  struct Sha256Encipher final
  {
    static constexpr bool BIG_ENDIAN = true;

    using WordType = uint;
    using VectorType = Array<uint, 8, 16>;
    
    Array<uint, 16> Matrix;
    
    VectorType Transform(VectorType vector) const noexcept;
    
    static VectorType Reset() noexcept;
  };
  
  using Sha256 = HashFunction<Sha256Encipher>;
  using HMacSha256 = HMac<Sha256>;
}
