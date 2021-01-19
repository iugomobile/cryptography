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
#include "igl/core/raw_stream.h"


namespace iugo
{
#pragma mark - HashError
  struct HashError final: DataError
  {
    StringRef Message() const noexcept final
    {
      return "Hash error";
    }
  };
}


namespace iugo::crypto
{
#pragma mark - HashFunction
  template<class T>
  struct HashFunction
  {
    using WordType = typename T::WordType;
    using StateType = typename T::VectorType;
    using BlockType = T;
    
    HashFunction() = default;
    HashFunction(ListRef<byte const> data) noexcept
    {
      Update(data);
    }
    
    auto& Update(ListRef<byte const> data) noexcept
    {
      auto i = mod2(uint(Count), sizeof(BlockType));
      auto _count = sizeof(BlockType) - i;
      
      Count += data.Count();
      
      if (data.Count() >= _count)
      {
        if (i > 0)
        {
          inc_copy(unsafe::ToRaw(Block).data(i), data(0, _count));
          if constexpr(raw::big_endian<T>)
          {
            for (auto& x : Block.Matrix)
            {
              x = bswap(x);
            }
          }
          Compress(Block);
          data += _count;
        }
        
        if (is_multiple2(data + 0, alignof(BlockType)))
        {
          while (data.Count() >= sizeof(BlockType))
          {
            auto block = *reinterpret_cast<BlockType const*>(data + 0);
            if constexpr(raw::big_endian<T>)
            {
              for (auto& x : block.Matrix)
              {
                x = bswap(x);
              }
            }
            Compress(block);
            data += sizeof(BlockType);
          }
        }
        else
        {
          while (data.Count() >= sizeof(BlockType))
          {
            BlockType block;
            inc_copy(unsafe::ToRaw(block).data, data(0, sizeof(BlockType)));
            if constexpr(raw::big_endian<T>)
            {
              for (auto& x : block.Matrix)
              {
                x = bswap(x);
              }
            }
            Compress(block);
            data += sizeof(BlockType);
          }
        }
        
        if (!data)
        {
          return *this;
        }
        
        i = 0;
      }
      
      inc_copy(unsafe::ToRaw(Block).data(i), data);
      return *this;
    }
    auto&& Digest() noexcept
    {
      static constexpr Array<byte, sizeof(BlockType), alignof(BlockType)> pad = {0x80_b};
      
      auto bits = Count << 3ull;
      if constexpr(raw::big_endian<T>)
      {
        bits = bswap(bits);
      }
      auto i = mod2(uint(Count), sizeof(BlockType));
      
      Update(pad(0, (i < sizeof(BlockType) - 8 ? sizeof(BlockType) - 8 : sizeof(BlockType) * 2 - 8) - i));
      Update(unsafe::ToRaw(bits).data);
      
      if constexpr(raw::big_endian<T>)
      {
        for (auto& x : State)
        {
          x = bswap(x);
        }
      }
      return move(unsafe::ToRaw(State).data);
    }
    
    auto& Reset() noexcept
    {
      State = T::Reset();
      Count = 0;
      return *this;
    }
    
  protected:
    StateType State = T::Reset();
    uint64 Count = 0;
    BlockType Block;
    
    void Compress(BlockType const& block) noexcept
    {
      auto state_ = block.Transform(State);
      
      for (uint i = 0; i < State.Count(); ++i)
      {
        State[i] += state_[i];
      }
    }
  };
  
  
#pragma mark - HMac
  template<class T>
  struct HMac: T
  {
    using typename T::WordType;
    using typename T::BlockType;
    
    using T::Update;
    
    HMac(ListRef<byte const> key) noexcept
    {
      if (key.Count() > sizeof(BlockType))
      {
        inc_copy(unsafe::ToRaw(Opad).data, Update(key).Digest());
        T::Reset();
      }
      else
      {
        inc_copy(unsafe::ToRaw(Opad).data, key);
      }
      
      fill_list(unsafe::ToRaw(Opad).data(key.Count()));
      
      for (uint i = 0; i < Opad.Matrix.Count(); ++i)
      {
        Ipad.Matrix[i] = Opad.Matrix[i] ^ WordType(0x3636363636363636ull);
        Opad.Matrix[i] ^= WordType(0x5c5c5c5c5c5c5c5cull);
      }
      
      Update(unsafe::ToRaw(Ipad).data);
    }
    HMac(ListRef<byte const> key, ListRef<byte const> data) noexcept
    : HMac{key}
    {
      Update(data);
    }
    
    decltype(auto) Digest() noexcept
    {
      auto hash = T::Digest();
      return T::Reset().Update(unsafe::ToRaw(Opad).data).Update(hash).Digest();
    }
    
    auto& Reset() noexcept
    {
      T::Reset().Update(unsafe::ToRaw(Ipad).data);
      return *this;
    }
    
  protected:
    BlockType Opad, Ipad;
  };
  
  
#pragma mark - Ecb
  namespace details
  {
    template<class T>
    struct Ecb: T
    {
      using BlockType = typename T::VectorType;
      
      using T::T;
      using T::Transform;
      
      void Reset() noexcept
      {
        Buffer = nullptr;
        Count = 0;
      }
      
    protected:
      List<byte> Buffer;
      uint Count = 0;
      
      void Update(ListRef<byte const> data, uint pad)
      {
        auto i = mod2(Count, sizeof(BlockType));
        auto _count = sizeof(BlockType) - i;
        
        auto count_ = Count + data.Count();
        resize(Buffer, ceil2(count_ + pad, sizeof(BlockType)));
        auto buffer = Buffer(Count - i);
        Count = count_;
        
        if (data.Count() >= _count)
        {
          if (i > 0)
          {
            inc_copy(buffer(i), data(0, _count));
            *reinterpret_cast<BlockType*>(buffer + 0) = Transform(*reinterpret_cast<BlockType const*>(buffer + 0));
            buffer += sizeof(BlockType);
            data += _count;
          }
          
          if (is_multiple2(data + 0, alignof(BlockType)))
          {
            while (data.Count() >= sizeof(BlockType))
            {
              *reinterpret_cast<BlockType*>(buffer + 0) = Transform(*reinterpret_cast<BlockType const*>(data + 0));
              buffer += sizeof(BlockType);
              data += sizeof(BlockType);
            }
          }
          else
          {
            while (data.Count() >= sizeof(BlockType))
            {
              BlockType block;
              inc_copy(unsafe::ToRaw(block).data, data(0, sizeof(BlockType)));
              *reinterpret_cast<BlockType*>(buffer + 0) = Transform(block);
              buffer += sizeof(BlockType);
              data += sizeof(BlockType);
            }
          }
          
          if (!data)
          {
            return;
          }
          
          i = 0;
        }
        
        inc_copy(buffer(i), data);
      }
    };
  }
  
  template<class T, class = int>
  struct Ecb: details::Ecb<T>
  {
    using KeyType = typename T::KeyType;
    using BlockType = typename details::Ecb<T>::BlockType;
    
    using details::Ecb<T>::Buffer;
    using details::Ecb<T>::Count;
    
    using details::Ecb<T>::Ecb;
    using details::Ecb<T>::Transform;
    
    Ecb(KeyType const& key, ListRef<byte const> src)
    : details::Ecb<T>{key}
    {
      Update(src);
    }
    
    auto& Update(ListRef<byte const> data)
    {
      details::Ecb<T>::Update(data, 1);
      return *this;
    }
    auto&& Text()
    {
      auto c = uint8(Buffer.Count() - Count);
      iglAssert(c > 0 && c <= sizeof(BlockType));
      fill_list(Buffer(Count), byte(c));
      
      auto i = Buffer.Count() - sizeof(BlockType);
      *reinterpret_cast<BlockType*>(Buffer + i) = Transform(*reinterpret_cast<BlockType const*>(Buffer + i));
      return move(Buffer);
    }
  };

  template<class T>
  struct Ecb<T, decltype(declval<typename T::KeyType::KeyType>(), int{})>: details::Ecb<T>
  {
    using KeyType = typename T::KeyType;
    
    using details::Ecb<T>::Buffer;
    
    using details::Ecb<T>::Ecb;
    
    Ecb(KeyType const& key, ListRef<byte const> src)
    : details::Ecb<T>{key}
    {
      Update(src);
    }
    
    auto& Update(ListRef<byte const> data)
    {
      details::Ecb<T>::Update(data, 0);
      return *this;
    }
    auto&& Text()
    {
      if (Buffer)
      {
        auto c = uint8(Last(Buffer));
        
        if (c > 0 && c <= Buffer.Count())
        {
          for (uint i = Buffer.Count() - c;; ++i)
          {
            if (i == Buffer.Count() - 1)
            {
              shrink(Buffer, c);
              return move(Buffer);
            }
            
            if (Buffer[i] != c)
            {
              break;
            }
          }
        }
      }
      
      iglMessage("Decryption failed.");
      throw DataError{};
    }
  };


#pragma mark - Cbc
  /// FIX properly implement Cbc
//  template<class T>
//  struct Cbc: Ecb<T>
//  {
//    using KeyType = typename T::KeyType;
//
//    Cbc(KeyType const& key, KeyType const& iv)
//    : Ecb<T>{key}
//    {
//      this->buffer = unsafe::ToRaw(iv).data;
//    }
//    Cbc(KeyType const& key, KeyType const& iv, ListRef<byte const> src)
//    : Cbc{key, iv}
//    {
//      Update(src);
//    }
//
//    auto& Update(ListRef<byte const> data)
//    {
//      Ecb<T>::Update(data, 0);
//      return *this;
//    }
//  };
}


namespace iugo
{
#pragma mark -
  igl_export std::size_t ciphertext_size(std::size_t size) noexcept;
  igl_export List<byte> encrypt(ListRef<byte const> data);
  igl_export List<byte> decrypt(ListRef<byte const> data);
}
