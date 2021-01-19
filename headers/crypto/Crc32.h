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
 * protected by trade secret or copyright law.
 */

#include "igl/core/string.h"


namespace iugo
{
#pragma mark - Crc32Hash
  using Crc32Hash = uint;
  
  
#pragma mark Crc32
  template<uint ReversedPolynomial = 0xedb88320>
  struct Crc32
  {
    static constexpr auto Table = []
    {
      Array<uint, 256> table{};
      
      for (uint i = 0; i < table.Count(); ++i)
      {
        auto checksum = i;
          
        for (uint i = 0; i < 8; ++i)
        {
          checksum = (checksum >> 1) ^ ((checksum & 1) ? ReversedPolynomial : 0);
        }
        
        table[i] = checksum;
      };
      
      return table;
    }();
    
    constexpr Crc32(uint hash = 0) noexcept
    : State{~hash}
    {
    }
    constexpr Crc32(ListRef<byte const> data, uint hash = 0) noexcept
    : State{~hash}
    {
      Update(data);
    }
    
    constexpr Crc32& Update(ListRef<byte const> data) noexcept
    {
      for (auto x : data)
      {
        State = Table[uint8(State ^ x)] ^ (State >> 8);
      }
      
      return *this;
    }
    constexpr uint Digest() noexcept
    {
      State = ~State;
      return State;
    }
    
    constexpr Crc32& Reset(uint hash = 0) noexcept
    {
      State = ~hash;
      return *this;
    }
    
  private:
    uint State;
  };
}
