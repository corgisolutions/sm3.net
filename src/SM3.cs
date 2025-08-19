/*
 * Pure C# implementation of the SM3 cryptographic hash algorithm (GBT.32905-2016)
 * Copyright (C) 2025, by @corgisolutions

 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

using System.Runtime.CompilerServices;
using System.Text;

/// <summary>
/// SM3 cryptographic hash algorithm implementation (GBT.32905-2016)
/// </summary>
public sealed class SM3
{
    private const int BlockSize = 64;
    private const int DigestSize = 32;
    private const uint IV0 = 0x7380166F;
    private const uint IV1 = 0x4914B2B9;
    private const uint IV2 = 0x172442D7;
    private const uint IV3 = 0xDA8A0600;
    private const uint IV4 = 0xA96F30BC;
    private const uint IV5 = 0x163138AA;
    private const uint IV6 = 0xE38DEE4D;
    private const uint IV7 = 0xB0FB0E4E;
    private const uint T0 = 0x79CC4519;
    private const uint T1 = 0x7A879D8A;

    private readonly uint[] _state = new uint[8];
    private readonly byte[] _buffer = new byte[BlockSize];
    private ulong _totalBits;
    private int _bytesBuffered;

    /// <summary>
    /// Gets the output hash size in bytes.
    /// </summary>
    public static int HashSize => DigestSize;

    /// <summary>
    /// Computes the SM3 hash for the input data.
    /// </summary>
    /// <param name="input">Input data to hash</param>
    /// <returns>32-byte SM3 hash</returns>
    public static byte[] ComputeHash(byte[] input)
    {
        var sm3 = new SM3();
        return sm3.ComputeHashInternal(input);
    }

    /// <summary>
    /// Computes the SM3 hash for the input string (UTF-8 encoded)
    /// </summary>
    /// <param name="input">String to hash</param>
    /// <returns>Hexadecimal string representation of the hash</returns>
    public static string ComputeHash(string input)
    {
        byte[] data = Encoding.UTF8.GetBytes(input);
        byte[] hash = ComputeHash(data);
        return BytesToHex(hash);
    }

    private SM3()
    {
        Initialize();
    }

    private byte[] ComputeHashInternal(byte[] input)
    {
        ProcessData(input, 0, input.Length);
        return FinalizeHash();
    }

    private void Initialize()
    {
        _state[0] = IV0;
        _state[1] = IV1;
        _state[2] = IV2;
        _state[3] = IV3;
        _state[4] = IV4;
        _state[5] = IV5;
        _state[6] = IV6;
        _state[7] = IV7;
        _totalBits = 0;
        _bytesBuffered = 0;
    }

    private void ProcessData(byte[] data, int offset, int count)
    {
        _totalBits += (ulong)count * 8;

        if (_bytesBuffered > 0)
        {
            int freeSpace = BlockSize - _bytesBuffered;
            if (count < freeSpace)
            {
                Array.Copy(data, offset, _buffer, _bytesBuffered, count);
                _bytesBuffered += count;
                return;
            }

            Array.Copy(data, offset, _buffer, _bytesBuffered, freeSpace);
            ProcessBlock(_buffer, 0);
            offset += freeSpace;
            count -= freeSpace;
            _bytesBuffered = 0;
        }

        while (count >= BlockSize)
        {
            ProcessBlock(data, offset);
            offset += BlockSize;
            count -= BlockSize;
        }

        if (count > 0)
        {
            Array.Copy(data, offset, _buffer, 0, count);
            _bytesBuffered = count;
        }
    }

    private byte[] FinalizeHash()
    {
        _buffer[_bytesBuffered] = 0x80;
        _bytesBuffered++;
        Array.Clear(_buffer, _bytesBuffered, BlockSize - _bytesBuffered);

        if (_bytesBuffered > BlockSize - 8)
        {
            ProcessBlock(_buffer, 0);
            Array.Clear(_buffer, 0, BlockSize);
            _bytesBuffered = 0;
        }

        for (int i = 0; i < 8; i++)
        {
            _buffer[BlockSize - 8 + i] = (byte)(_totalBits >> (56 - i * 8));
        }

        ProcessBlock(_buffer, 0);

        byte[] digest = new byte[DigestSize];
        for (int i = 0; i < 8; i++)
        {
            digest[i * 4] = (byte)(_state[i] >> 24);
            digest[i * 4 + 1] = (byte)(_state[i] >> 16);
            digest[i * 4 + 2] = (byte)(_state[i] >> 8);
            digest[i * 4 + 3] = (byte)_state[i];
        }

        return digest;
    }

    private unsafe void ProcessBlock(byte[] block, int offset)
    {
        uint* w = stackalloc uint[68];
        uint* ww = stackalloc uint[64];
        uint a = _state[0], b = _state[1], c = _state[2], d = _state[3];
        uint e = _state[4], f = _state[5], g = _state[6], h = _state[7];

        fixed (byte* ptr = block)
        {
            byte* p = ptr + offset;
            for (int i = 0; i < 16; i++)
            {
                w[i] = (uint)(
                    (p[i * 4] << 24) |
                    (p[i * 4 + 1] << 16) |
                    (p[i * 4 + 2] << 8) |
                    p[i * 4 + 3]
                );
            }
        }

        for (int j = 16; j < 68; j++)
        {
            w[j] = P1(w[j - 16] ^ w[j - 9] ^ Rol(w[j - 3], 15))
                   ^ Rol(w[j - 13], 7)
                   ^ w[j - 6];
        }

        for (int j = 0; j < 64; j++)
        {
            ww[j] = w[j] ^ w[j + 4];
        }

        for (int j = 0; j < 64; j++)
        {
            uint tt = j < 16 ? T0 : T1;
            uint ss1 = Rol(Rol(a, 12) + e + Rol(tt, j), 7);
            uint ss2 = ss1 ^ Rol(a, 12);
            uint tt1 = (j < 16 ? FF0(a, b, c) : FF1(a, b, c)) + d + ss2 + ww[j];
            uint tt2 = (j < 16 ? GG0(e, f, g) : GG1(e, f, g)) + h + ss1 + w[j];
            d = c;
            c = Rol(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = Rol(f, 19);
            f = e;
            e = P0(tt2);
        }

        _state[0] ^= a;
        _state[1] ^= b;
        _state[2] ^= c;
        _state[3] ^= d;
        _state[4] ^= e;
        _state[5] ^= f;
        _state[6] ^= g;
        _state[7] ^= h;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Rol(uint x, int n) => (x << n) | (x >> (32 - n));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint FF0(uint x, uint y, uint z) => x ^ y ^ z;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint FF1(uint x, uint y, uint z) => (x & y) | (x & z) | (y & z);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint GG0(uint x, uint y, uint z) => x ^ y ^ z;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint GG1(uint x, uint y, uint z) => (x & y) | (~x & z);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint P0(uint x) => x ^ Rol(x, 9) ^ Rol(x, 17);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint P1(uint x) => x ^ Rol(x, 15) ^ Rol(x, 23);

    private static string BytesToHex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
        {
            sb.AppendFormat("{0:x2}", b);
        }

        return sb.ToString();
    }
}