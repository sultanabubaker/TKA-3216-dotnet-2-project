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
using GoodId.Core.Helpers.Key;
using System.Net.Http;
using System.Threading.Tasks;

namespace GoodId.Core.Helpers.OpenIdRequestSources
{
    public class OpenIdRequestUri : OpenIdRequestSource
    {
        public string RequestUri { get; }

        public OpenIdRequestUri(string requestUri)
        {
            this.RequestUri = requestUri;
        }

        public async Task<string> ToJsonAsync(RsaPublicKey sigPubKey)
        {
            var jwt = await RetrieveUriContentsAsync(RequestUri);

            if (Util.IsCompactJwe(jwt))
            {
                return CONTENT_IS_ENCRYPTED;
            }

            return sigPubKey.VerifyCompactJws(jwt);
        }

        async Task<string> RetrieveUriContentsAsync(string requestUri)
        {
            using (var client = new HttpClient())
            {
                return await client.GetStringAsync(requestUri);
            }
        }
    }
}
