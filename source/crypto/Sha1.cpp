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

#include "igl/crypto/Sha1.h"


namespace iugo::crypto
{
#pragma mark - Sha1Encipher
  Sha1Encipher::VectorType Sha1Encipher::Transform(VectorType vector) const noexcept
  {
    /// FIX C++17 tuple_size
    auto& [A, B, C, D, E] = vector.data;
    auto W = Matrix;
    
    constexpr auto F = [](uint x, uint y, uint z)
    {
      return (x & (y ^ z)) ^ z;
    };
    constexpr auto G = [](uint x, uint y, uint z)
    {
      return x ^ y ^ z;
    };
    constexpr auto H = [](uint x, uint y, uint z)
    {
      return (x & y) | ((x | y) & z);
    };
    
    constexpr auto P = [](auto&& f, uint& v, uint w, uint& x, uint y, uint z, uint i, uint k)
    {
      v += rotl(w, 5) + f(x, y, z) + i + k;
      x = rotl(x, 30);
    };
    
    auto R = [&](uint t)
    {
      return W[t & 0xf] = rotl(W[(t - 3) & 0xf] ^ W[(t - 8) & 0xf] ^ W[(t - 14) & 0xf] ^ W[t & 0xf], 1);
    };
    
    /// Round 1
    auto R1 = [&](uint& v, uint w, uint& x, uint y, uint z, uint i)
    {
      P(F, v, w, x, y, z, i, 0x5a827999);
    };
    R1(E, A, B, C, D, W[ 0]);
    R1(D, E, A, B, C, W[ 1]);
    R1(C, D, E, A, B, W[ 2]);
    R1(B, C, D, E, A, W[ 3]);
    R1(A, B, C, D, E, W[ 4]);
    R1(E, A, B, C, D, W[ 5]);
    R1(D, E, A, B, C, W[ 6]);
    R1(C, D, E, A, B, W[ 7]);
    R1(B, C, D, E, A, W[ 8]);
    R1(A, B, C, D, E, W[ 9]);
    R1(E, A, B, C, D, W[10]);
    R1(D, E, A, B, C, W[11]);
    R1(C, D, E, A, B, W[12]);
    R1(B, C, D, E, A, W[13]);
    R1(A, B, C, D, E, W[14]);
    R1(E, A, B, C, D, W[15]);
    R1(D, E, A, B, C, R(16));
    R1(C, D, E, A, B, R(17));
    R1(B, C, D, E, A, R(18));
    R1(A, B, C, D, E, R(19));
    
    /// Round 2
    auto R2 = [&](uint& v, uint w, uint& x, uint y, uint z, uint i)
    {
      P(G, v, w, x, y, z, i, 0x6ed9eba1);
    };
    R2(E, A, B, C, D, R(20));
    R2(D, E, A, B, C, R(21));
    R2(C, D, E, A, B, R(22));
    R2(B, C, D, E, A, R(23));
    R2(A, B, C, D, E, R(24));
    R2(E, A, B, C, D, R(25));
    R2(D, E, A, B, C, R(26));
    R2(C, D, E, A, B, R(27));
    R2(B, C, D, E, A, R(28));
    R2(A, B, C, D, E, R(29));
    R2(E, A, B, C, D, R(30));
    R2(D, E, A, B, C, R(31));
    R2(C, D, E, A, B, R(32));
    R2(B, C, D, E, A, R(33));
    R2(A, B, C, D, E, R(34));
    R2(E, A, B, C, D, R(35));
    R2(D, E, A, B, C, R(36));
    R2(C, D, E, A, B, R(37));
    R2(B, C, D, E, A, R(38));
    R2(A, B, C, D, E, R(39));
    
    /// Round 3
    auto R3 = [&](uint& v, uint w, uint& x, uint y, uint z, uint i)
    {
      P(H, v, w, x, y, z, i, 0x8f1bbcdc);
    };
    R3(E, A, B, C, D, R(40));
    R3(D, E, A, B, C, R(41));
    R3(C, D, E, A, B, R(42));
    R3(B, C, D, E, A, R(43));
    R3(A, B, C, D, E, R(44));
    R3(E, A, B, C, D, R(45));
    R3(D, E, A, B, C, R(46));
    R3(C, D, E, A, B, R(47));
    R3(B, C, D, E, A, R(48));
    R3(A, B, C, D, E, R(49));
    R3(E, A, B, C, D, R(50));
    R3(D, E, A, B, C, R(51));
    R3(C, D, E, A, B, R(52));
    R3(B, C, D, E, A, R(53));
    R3(A, B, C, D, E, R(54));
    R3(E, A, B, C, D, R(55));
    R3(D, E, A, B, C, R(56));
    R3(C, D, E, A, B, R(57));
    R3(B, C, D, E, A, R(58));
    R3(A, B, C, D, E, R(59));
    
    /// Round 4
    auto R4 = [&](uint& v, uint w, uint& x, uint y, uint z, uint i)
    {
      P(G, v, w, x, y, z, i, 0xca62c1d6);
    };
    R4(E, A, B, C, D, R(60));
    R4(D, E, A, B, C, R(61));
    R4(C, D, E, A, B, R(62));
    R4(B, C, D, E, A, R(63));
    R4(A, B, C, D, E, R(64));
    R4(E, A, B, C, D, R(65));
    R4(D, E, A, B, C, R(66));
    R4(C, D, E, A, B, R(67));
    R4(B, C, D, E, A, R(68));
    R4(A, B, C, D, E, R(69));
    R4(E, A, B, C, D, R(70));
    R4(D, E, A, B, C, R(71));
    R4(C, D, E, A, B, R(72));
    R4(B, C, D, E, A, R(73));
    R4(A, B, C, D, E, R(74));
    R4(E, A, B, C, D, R(75));
    R4(D, E, A, B, C, R(76));
    R4(C, D, E, A, B, R(77));
    R4(B, C, D, E, A, R(78));
    R4(A, B, C, D, E, R(79));
    
    return vector;
  }
  
  Sha1Encipher::VectorType Sha1Encipher::Reset() noexcept
  {
    return {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u};
  }
}
