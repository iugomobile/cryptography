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

#include "igl/crypto/Md5.h"


namespace iugo::crypto
{
#pragma mark - Md5Encipher
  Md5Encipher::VectorType Md5Encipher::Transform(VectorType vector) const noexcept
  {
    /// FIX C++17 tuple_size
    auto& [A, B, C, D] = vector.data;
    auto& X = Matrix;
    
    constexpr auto F = [](uint x, uint y, uint z)
    {
      return ((y ^ z) & x) ^ z;
    };
    constexpr auto G = [](uint x, uint y, uint z)
    {
      return ((x ^ y) & z) ^ y;
    };
    constexpr auto H = [](uint x, uint y, uint z)
    {
      return x ^ y ^ z;
    };
    constexpr auto I = [](uint x, uint y, uint z)
    {
      return (~z | x) ^ y;
    };
    
    constexpr auto P = [](auto&& f, uint& w, uint x, uint y, uint z, uint i, uint s, uint k)
    {
      w = rotl(w + f(x, y, z) + i + k, s) + x;
    };
    
    /// Round 1
    auto R1 = [&](uint& w, uint x, uint y, uint z, uint i, uint s, uint k)
    {
      P(F, w, x, y, z, i, s, k);
    };
    R1(A, B, C, D, X[ 0],  7, 0xd76aa478);
    R1(D, A, B, C, X[ 1], 12, 0xe8c7b756);
    R1(C, D, A, B, X[ 2], 17, 0x242070db);
    R1(B, C, D, A, X[ 3], 22, 0xc1bdceee);
    R1(A, B, C, D, X[ 4],  7, 0xf57c0faf);
    R1(D, A, B, C, X[ 5], 12, 0x4787c62a);
    R1(C, D, A, B, X[ 6], 17, 0xa8304613);
    R1(B, C, D, A, X[ 7], 22, 0xfd469501);
    R1(A, B, C, D, X[ 8],  7, 0x698098d8);
    R1(D, A, B, C, X[ 9], 12, 0x8b44f7af);
    R1(C, D, A, B, X[10], 17, 0xffff5bb1);
    R1(B, C, D, A, X[11], 22, 0x895cd7be);
    R1(A, B, C, D, X[12],  7, 0x6b901122);
    R1(D, A, B, C, X[13], 12, 0xfd987193);
    R1(C, D, A, B, X[14], 17, 0xa679438e);
    R1(B, C, D, A, X[15], 22, 0x49b40821);
    
    /// Round 2
    auto R2 = [&](uint& w, uint x, uint y, uint z, uint i, uint s, uint k)
    {
      P(G, w, x, y, z, i, s, k);
    };
    R2(A, B, C, D, X[ 1],  5, 0xf61e2562);
    R2(D, A, B, C, X[ 6],  9, 0xc040b340);
    R2(C, D, A, B, X[11], 14, 0x265e5a51);
    R2(B, C, D, A, X[ 0], 20, 0xe9b6c7aa);
    R2(A, B, C, D, X[ 5],  5, 0xd62f105d);
    R2(D, A, B, C, X[10],  9, 0x02441453);
    R2(C, D, A, B, X[15], 14, 0xd8a1e681);
    R2(B, C, D, A, X[ 4], 20, 0xe7d3fbc8);
    R2(A, B, C, D, X[ 9],  5, 0x21e1cde6);
    R2(D, A, B, C, X[14],  9, 0xc33707d6);
    R2(C, D, A, B, X[ 3], 14, 0xf4d50d87);
    R2(B, C, D, A, X[ 8], 20, 0x455a14ed);
    R2(A, B, C, D, X[13],  5, 0xa9e3e905);
    R2(D, A, B, C, X[ 2],  9, 0xfcefa3f8);
    R2(C, D, A, B, X[ 7], 14, 0x676f02d9);
    R2(B, C, D, A, X[12], 20, 0x8d2a4c8a);
    
    /// Round 3
    auto R3 = [&](uint& w, uint x, uint y, uint z, uint i, uint s, uint k)
    {
      P(H, w, x, y, z, i, s, k);
    };
    R3(A, B, C, D, X[ 5],  4, 0xfffa3942);
    R3(D, A, B, C, X[ 8], 11, 0x8771f681);
    R3(C, D, A, B, X[11], 16, 0x6d9d6122);
    R3(B, C, D, A, X[14], 23, 0xfde5380c);
    R3(A, B, C, D, X[ 1],  4, 0xa4beea44);
    R3(D, A, B, C, X[ 4], 11, 0x4bdecfa9);
    R3(C, D, A, B, X[ 7], 16, 0xf6bb4b60);
    R3(B, C, D, A, X[10], 23, 0xbebfbc70);
    R3(A, B, C, D, X[13],  4, 0x289b7ec6);
    R3(D, A, B, C, X[ 0], 11, 0xeaa127fa);
    R3(C, D, A, B, X[ 3], 16, 0xd4ef3085);
    R3(B, C, D, A, X[ 6], 23, 0x04881d05);
    R3(A, B, C, D, X[ 9],  4, 0xd9d4d039);
    R3(D, A, B, C, X[12], 11, 0xe6db99e5);
    R3(C, D, A, B, X[15], 16, 0x1fa27cf8);
    R3(B, C, D, A, X[ 2], 23, 0xc4ac5665);
    
    /// Round 4
    auto R4 = [&](uint& w, uint x, uint y, uint z, uint i, uint s, uint k)
    {
      P(I, w, x, y, z, i, s, k);
    };
    R4(A, B, C, D, X[ 0],  6, 0xf4292244);
    R4(D, A, B, C, X[ 7], 10, 0x432aff97);
    R4(C, D, A, B, X[14], 15, 0xab9423a7);
    R4(B, C, D, A, X[ 5], 21, 0xfc93a039);
    R4(A, B, C, D, X[12],  6, 0x655b59c3);
    R4(D, A, B, C, X[ 3], 10, 0x8f0ccc92);
    R4(C, D, A, B, X[10], 15, 0xffeff47d);
    R4(B, C, D, A, X[ 1], 21, 0x85845dd1);
    R4(A, B, C, D, X[ 8],  6, 0x6fa87e4f);
    R4(D, A, B, C, X[15], 10, 0xfe2ce6e0);
    R4(C, D, A, B, X[ 6], 15, 0xa3014314);
    R4(B, C, D, A, X[13], 21, 0x4e0811a1);
    R4(A, B, C, D, X[ 4],  6, 0xf7537e82);
    R4(D, A, B, C, X[11], 10, 0xbd3af235);
    R4(C, D, A, B, X[ 2], 15, 0x2ad7d2bb);
    R4(B, C, D, A, X[ 9], 21, 0xeb86d391);
    
    return vector;
  }
  
  Md5Encipher::VectorType Md5Encipher::Reset() noexcept
  {
    return {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
  }
}
