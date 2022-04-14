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
using GoodId.Core.Helpers.Key;

namespace GoodId.Core.Helpers.OpenIdRequestSources
{
    public class OpenIdRequestObjectJwt : OpenIdRequestSource
    {
        public string Jwt { get; }

        public OpenIdRequestObjectJwt(string jwt)
        {
            Jwt = jwt;
        }

        public string ToJson(RsaPublicKey sigPubKey)
        {
            if (Util.IsCompactJwe(Jwt))
            {
                return Util.Jsonize(CONTENT_IS_ENCRYPTED);
            }
            if (Util.IsCompactJws(Jwt))
            {
                return sigPubKey.VerifyCompactJws(Jwt);
            }

            throw new GoodIdException("Unsupported JWT format.");
        }
    }
}
