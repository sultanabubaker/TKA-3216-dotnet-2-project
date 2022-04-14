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
using GoodId.Core.Exceptions;
using Jose;
using System.Collections.Generic;

namespace GoodId.Core.Helpers.Key
{
    public class RsaPrivateKey : RsaPublicKey
    {
        protected RsaPrivateKey(string key, KeyFormat format)
            : base(key, format)
        {
            if (!mHasPrivateParameters)
            {
                throw new GoodIdException("This is not a private key.");
            }
        }

        // TODO Support JWK also
        public static new RsaPrivateKey FromPem(string pem)
        {
            return new RsaPrivateKey(pem, KeyFormat.PEM);
        }

        internal string SignAsCompactJws(string payload)
        {
            var extraHeaders = new Dictionary<string, object> { // "alg" parameter is implicitly there
                {"kid", GetKid()}
            };

            return JWT.Encode(payload, mKey, JwsAlgorithm.RS256, extraHeaders);
        }

        internal string DecryptCompactJwe(string compactJwe)
        {
            return JWT.Decode(compactJwe, mKey);
        }
    }
}
