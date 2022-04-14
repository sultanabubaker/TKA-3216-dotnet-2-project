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
using GoodId.Core.Helpers.Response;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace GoodId.Core.Helpers.Request
{
    class UserinfoRequest
    {
        string mAccessToken;

        GoodIdServerConfig mGoodIdServerConfig;

        internal UserinfoRequest(string accessToken, GoodIdServerConfig config)
        {
            mAccessToken = accessToken;
            mGoodIdServerConfig = config;
        }

        internal async Task<UserinfoResponse> ExecuteAsync()
        {
            var userinfoResponse = await CallEndpointAsync(
                mGoodIdServerConfig.UserinfoEndpointUri,
                mAccessToken
            );

            var statusCode = userinfoResponse.Item1;
            var authError = userinfoResponse.Item2;
            var responseString = userinfoResponse.Item3;

            if (authError)
            {
                throw new GoodIdException("Authentication failed to userinfo endpoint.");
            }

            if (statusCode != HttpStatusCode.OK)
            {
                throw new GoodIdException("Userinfo endpoint http status code: " + (int)statusCode);
            }

            return new UserinfoResponse(responseString);
        }

        internal async Task<Tuple<HttpStatusCode, bool, string>> CallEndpointAsync(
            string endpointUri,
            string accessToken)
        {
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Get, endpointUri);

                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

                var response = await client.SendAsync(request);

                var wwwAuthenticateHeader = response.Headers.WwwAuthenticate;

                var authError = (wwwAuthenticateHeader != null && wwwAuthenticateHeader.Any(v => v.Parameter.ToLower().Contains("error")));

                return new Tuple<HttpStatusCode, bool, string>(response.StatusCode, authError, await response.Content.ReadAsStringAsync());
            }
        }
    }
}
