/*
 * Copyright (c) 2019 Rafael Almeida
 * Copyright (c) 2012 Markus Ullmark
 * 
 * MIT License
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

using System.Collections.Generic;

namespace HashidsCore.NET
{
    /// <summary>
    /// Describes a Hashids provider
    /// </summary>
    public interface IHashids
    {
        /// <summary>
        /// Decodes the provided hashed string.
        /// </summary>
        /// <param name="hash">the hashed string</param>
        /// <exception cref="T:System.OverflowException">if one or many of the numbers in the hash overflowing the integer storage</exception>
        /// <returns>the numbers</returns>
        int[] Decode(string hash);

        /// <summary>
        /// Decodes the provided hashed string into longs
        /// </summary>
        /// <param name="hash">the hashed string</param>
        /// <returns>the numbers</returns>
        long[] DecodeLong(string hash);

        /// <summary>
        /// Decodes the provided hashed string into a hex string
        /// </summary>
        /// <param name="hash">the hashed string</param>
        /// <returns>the hex string</returns>
        string DecodeHex(string hash);

        /// <summary>
        /// Encodes the provided numbers into a hashed string
        /// </summary>
        /// <param name="numbers">the numbers</param>
        /// <returns>the hashed string</returns>
        string Encode(params int[] numbers);

        /// <summary>
        /// Encodes the provided numbers into a hashed string
        /// </summary>
        /// <param name="numbers">the numbers</param>
        /// <returns>the hashed string</returns>
        string Encode(IEnumerable<int> numbers);

        /// <summary>
        /// Encodes the provided numbers into a hashed string
        /// </summary>
        /// <param name="numbers">the numbers</param>
        /// <returns>the hashed string</returns>
        string EncodeLong(params long[] numbers);

        /// <summary>
        /// Encodes the provided numbers into a hashed string
        /// </summary>
        /// <param name="numbers">the numbers</param>
        /// <returns>the hashed string</returns>
        string EncodeLong(IEnumerable<long> numbers);

        /// <summary>
        /// Encodes the provided hex string
        /// </summary>
        /// <param name="hex">the hex string</param>
        /// <returns>the hashed string</returns>
        string EncodeHex(string hex);
    }
}
