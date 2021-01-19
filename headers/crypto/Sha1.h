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
#pragma mark - Sha1Hash
  using Sha1Hash = Array<byte, 20, 4>;
  
  
#pragma mark - Sha1Encipher
  struct igl_export Sha1Encipher final
  {
    static constexpr bool BIG_ENDIAN = true;

    using WordType = uint;
    using VectorType = Array<uint, 5>;
    
    Array<uint, 16> Matrix;
    
    VectorType Transform(VectorType vector) const noexcept;
    
    static VectorType Reset() noexcept;
  };
  
  using Sha1 = HashFunction<Sha1Encipher>;
  using HMacSha1 = HMac<Sha1>;
}
