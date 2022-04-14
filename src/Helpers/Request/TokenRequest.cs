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
using GoodId.Core.AbstractClasses;
using GoodId.Core.Exceptions;
using GoodId.Core.Helpers.Response;
using Jose;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace GoodId.Core.Helpers.Request
{
    class TokenRequest
    {
        string mAuthCode;

        string mRedirectUri;

        string mClientId;

        string mClientSecret;

        string mRequestUriForValidation;

        GoodIdServerConfig mGoodIdServerConfig;

        Logger mLogger;

        internal TokenRequest(
            string clientId,
            string clientSecret,
            string redirectUri,
            string authCode,
            string requestUriForValidation,
            GoodIdServerConfig goodIdServerConfig,
            Logger logger
        )
        {
            mGoodIdServerConfig = goodIdServerConfig;
            mAuthCode = authCode;
            mRedirectUri = redirectUri;
            mClientId = clientId;
            mClientSecret = clientSecret;
            mRequestUriForValidation = requestUriForValidation;
            mLogger = logger;
        }

        internal async Task<TokenResponse> ExecuteAsync()
        {
            var responseTuple = await CallEndpointAsync(
                mGoodIdServerConfig.TokenEndpointUri,
                mAuthCode,
                mRedirectUri,
                mClientId,
                mClientSecret,
                mRequestUriForValidation
            );

            var statusCode = responseTuple.Item1;
            var responseString = responseTuple.Item2;

            JObject response;

            try
            {
                response = JObject.Parse(responseString);
            }
            catch (Exception)
            {
                throw new GoodIdException("The GoodId Token Endpoint response returned invalid JSON.");
            }
            HandleErrorResponse(statusCode, response);

            ValidateResponseContent(response);

            return new TokenResponse(
                (string)response["access_token"],
                (string)response["id_token"],
                (long)response["server_time"]);
        }

        internal async Task<Tuple<HttpStatusCode, string>> CallEndpointAsync(
            string endpointUri,
            string authCode,
            string redirectUri,
            string clientId,
            string clientSecret,
            string requestUriForValidation
        )
        {
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Post, endpointUri);

                var password = Convert.ToBase64String(Encoding.ASCII.GetBytes(
                    Uri.EscapeDataString(clientId) + ":" + Uri.EscapeDataString(clientSecret)));

                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", password);
                var extString = $"{{\"sdk_version\":{Config.GOODID_SDK_VERSION}, \"profile_version\":{Config.GOODID_PROFILE_VERSION}}}";
                var parameters = new Dictionary<String, String>{
                    {"grant_type", "authorization_code"},
                    {"code", authCode},
                    {"redirect_uri", redirectUri},
                    {"client_id", clientId},
                    {"ext", Base64Url.Encode(Encoding.UTF8.GetBytes(extString))}
                };

                if (requestUriForValidation != null)
                {
                    parameters["request_uri_for_validation"] = requestUriForValidation;
                }

                request.Content = new FormUrlEncodedContent(parameters);

                var response = await client.SendAsync(request);
                return new Tuple<HttpStatusCode, string>(response.StatusCode, await response.Content.ReadAsStringAsync());
            }
        }

        void HandleErrorResponse(HttpStatusCode statusCode, JObject response)
        {
            if (response["error"] != null)
            {
                var errorString = (string)response["error"];
                if (response["error_description"] != null)
                {
                    errorString += " " + (string)response["error_description"];
                }
                if (response["error_uri"] != null)
                {
                    errorString += " See" + response["error_uri"];
                }
                if (response["error_type"] != null && (string)response["error_type"] == "warning")
                {
                    mLogger.Log(Logger.Level.WARNING, errorString);
                }
                else
                {
                    throw new GoodIdException("GoodID Token Endpoint Error: " + errorString);
                }

                if (statusCode != HttpStatusCode.OK)
                {
                    throw new GoodIdException("Token endpoint http status code: " + (int)statusCode);
                }
            }
        }

        void ValidateResponseContent(JObject response)
        {
            var error = false;
            error = error || response["id_token"] == null || response["id_token"].Type != JTokenType.String;
            error = error || response["server_time"] == null || response["server_time"].Type != JTokenType.Integer;

            if (response["access_token"] != null)
            {
                error = error || response["access_token"].Type != JTokenType.String;
                error = error || response["token_type"] == null || (string)response["token_type"] != "Bearer";
            }

            if (error)
            {
                throw new GoodIdException("Token response content error. " + response);
            }
        }
    }
}
