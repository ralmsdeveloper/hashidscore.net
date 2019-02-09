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

using System;
using System.Collections.Generic;
using Xunit;

namespace HashidsCore.NET.Tests
{
    public class Hashids_issues
    {
        [Fact]
        void issue_8_should_not_throw_out_of_range_exception()
        {
            var hashids = new Hashids("janottaa", 6);
            var numbers = hashids.Decode("NgAzADEANAA=");
        }

        // This issue came from downcasting to int at the wrong place,
        // seems to happen when you are encoding A LOT of longs at the same time.
        // see if it is possible to make this a faster test (or remove it since it is unlikely that it will reapper).
        [Fact]
        void issue_12_should_not_throw_out_of_range_exception()
        {
            var hash = new Hashids("zXZVFf2N38uV");
            var longs = new List<long>();
            var rand = new Random();
            var valueBuffer = new byte[8];
            var randLong = 0L;
            for (var i = 0; i < 100000; i++)
            {
                rand.NextBytes(valueBuffer);
                randLong = BitConverter.ToInt64(valueBuffer, 0);
                longs.Add(Math.Abs(randLong));
            }

            var encoded = hash.EncodeLong(longs);
            var decoded = hash.DecodeLong(encoded);

            Assert.Equal(decoded, longs.ToArray());
        }

        [Fact]
        void issue_14_it_should_decode_encode_hex_correctly()
        {
            var hashids = new Hashids("this is my salt");
            var encoded = hashids.EncodeHex("DEADBEEF");
            Assert.Equal("kRNrpKlJ", encoded);

            var decoded = hashids.DecodeHex(encoded);
            Assert.Equal("DEADBEEF", decoded);

            var encoded2 = hashids.EncodeHex("1234567890ABCDEF");
            var decoded2 = hashids.DecodeHex(encoded2);
            Assert.Equal("1234567890ABCDEF", decoded2);
        }

        [Fact]
        void issue_18_it_should_return_empty_string_if_negative_numbers()
        {
            var hashids = new Hashids("this is my salt");
            Assert.Equal(hashids.Encode(1, 4, 5, -3), string.Empty);
            Assert.Equal(hashids.EncodeLong(4, 5, 2, -4), string.Empty);
        }

        [Fact]
        void issue_15_it_should_return_emtpy_array_when_decoding_characters_missing_in_alphabet()
        {
            var hashids = new Hashids(salt: "Salty stuff", alphabet: "qwerty1234!¤%&/()=", seps: "1234");
            var numbers = hashids.Decode("abcd");
            Assert.Empty(numbers);
            Assert.Empty(hashids.Decode("13-37"));
            Assert.Empty(hashids.DecodeLong("32323kldffd!"));
            Assert.Empty(hashids.Decode("asdfb"));
            Assert.Empty(hashids.DecodeLong("asdfgfdgdfgkj"));
        }
    }
}
