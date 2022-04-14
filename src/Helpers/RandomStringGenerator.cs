///
/// Copyright 2017 ID&Trust, Ltd.
///
/// You are hereby granted a non-exclusive, worldwide, royalty-free license to
/// use, copy, modify, and distribute this software in source code or binary form
/// for use in connection with the web services and APIs provided by ID&Trust.
///
/// As with any software that integrates with the GoodID platform, your use
/// of this software is subject to the GoodID Terms of Service
/// (https://goodid.net/docs/tos).
/// This copyright notice shall be included in all copies or substantial portions
/// of the software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
/// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
/// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
/// DEALINGS IN THE SOFTWARE.
///
using System;
using System.Security.Cryptography;
using System.Text;

namespace GoodId.Core.Helpers
{
    public class RandomStringGenerator
    {
        // TODO consider static, if it is thread-safe
        readonly RNGCryptoServiceProvider mRng = new RNGCryptoServiceProvider();
        readonly byte[] mBuffer = new byte[sizeof(UInt32)];

        Int32 Next(Int32 minValue, Int32 maxValueExclusive)
        {
            if (minValue > maxValueExclusive)
            {
                throw new ArgumentOutOfRangeException(nameof(minValue));
            }

            if (minValue == maxValueExclusive)
            {
                return minValue;
            }

            Int64 diff = maxValueExclusive - minValue;
            while (true)
            {
                mRng.GetBytes(mBuffer);
                UInt32 rand = BitConverter.ToUInt32(mBuffer, 0);

                Int64 max = (1 + (Int64)UInt32.MaxValue);
                Int64 remainder = max % diff;
                if (rand < max - remainder)
                {
                    return (Int32)(minValue + (rand % diff));
                }
            }
        }

        internal string GetPseudoRandomString(int length, string keyspace = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
        {
            StringBuilder stringBuilder = new StringBuilder();

            for (int i = 0; i < length; i++)
            {
                stringBuilder.Append(keyspace[Next(0, keyspace.Length)]);
            }

            return stringBuilder.ToString();
        }
    }
}
