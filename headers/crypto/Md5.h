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
#pragma mark - Md5Hash
  using Md5Hash = Array<byte, 16, 16>;
  
  
#pragma mark - Md5Encipher
  struct Md5Encipher final
  {
    using WordType = uint;
    using VectorType = Array<uint, 4, 16>;
    
    Array<uint, 16> Matrix;
    
    VectorType Transform(VectorType vector) const noexcept;
    
    static VectorType Reset() noexcept;
  };
  
  using Md5 = HashFunction<Md5Encipher>;
  using HMacMd5 = HMac<Md5>;
}
