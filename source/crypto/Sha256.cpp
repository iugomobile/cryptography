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

#include "igl/crypto/Sha256.h"


namespace iugo::crypto
{
#pragma mark - Sha256Encipher
  Sha256Encipher::VectorType Sha256Encipher::Transform(VectorType vector) const noexcept
  {
    auto& A = vector;
    auto W = Matrix;
    
    constexpr Array K =
    {
      0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
      0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
      0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
      0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
      0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
      0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
      0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
      0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
      0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
      0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
      0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
      0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
      0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
      0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
      0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
      0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };
    
    constexpr auto S0 = [](uint x)
    {
      return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    };
    constexpr auto S1 = [](uint x)
    {
      return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    };
    constexpr auto S2 = [](uint x)
    {
      return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    };
    constexpr auto S3 = [](uint x)
    {
      return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    };
    
    constexpr auto F0 = [](uint x, uint y, uint z)
    {
      return (x & y) | (z & (x | y));
    };
    constexpr auto F1 = [](uint x, uint y, uint z)
    {
      return z ^ (x & (y ^ z));
    };
    
    auto P = [&](uint a, uint b, uint c, uint& d, uint e, uint f, uint g, uint& h, uint x, uint K)
    {
      auto tmp1 = h + S3(e) + F1(e, f, g) + K + x;
      auto tmp2 = S2(a) + F0(a, b, c);
      d += tmp1;
      h = tmp1 + tmp2;
    };
    
    auto R = [&](uint t)
    {
      return W[t & 0xf] = S1(W[(t - 2) & 0xf]) + W[(t - 7) & 0xf] + S0(W[(t - 15) & 0xf]) + W[t & 0xf];
    };
    
    for (uint i = 0; i < 16; i += 8)
    {
      P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], W[i + 0], K[i + 0]);
      P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], W[i + 1], K[i + 1]);
      P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], W[i + 2], K[i + 2]);
      P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], W[i + 3], K[i + 3]);
      P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], W[i + 4], K[i + 4]);
      P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], W[i + 5], K[i + 5]);
      P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], W[i + 6], K[i + 6]);
      P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], W[i + 7], K[i + 7]);
    }
    
    for (uint i = 16; i < 64; i += 8)
    {
      P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], R(i + 0), K[i + 0]);
      P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], R(i + 1), K[i + 1]);
      P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], R(i + 2), K[i + 2]);
      P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], R(i + 3), K[i + 3]);
      P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], R(i + 4), K[i + 4]);
      P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], R(i + 5), K[i + 5]);
      P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], R(i + 6), K[i + 6]);
      P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], R(i + 7), K[i + 7]);
    }
    
    return vector;
  }
  
  Sha256Encipher::VectorType Sha256Encipher::Reset() noexcept
  {
    return {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
  }
}
