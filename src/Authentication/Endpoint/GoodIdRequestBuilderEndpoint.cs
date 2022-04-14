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
using GoodId.Core.Helpers;
using GoodId.Core.Helpers.HttpResponses;
using GoodId.Core.Helpers.Key;
using GoodId.Core.Helpers.OpenIdRequestSources;
using Jose;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace GoodId.Core.Authentication.Endpoint
{

    /// <summary
    /// This class is responsible to build the Authentication Request
    /// <see cref="http://openid.net/specs/openid-connect-core-1_0.html#AuthReques"/>
    public class GoodIdRequestBuilderEndpoint : GoodIdEndpoint
    {
        internal GoodIdRequestBuilderEndpoint(
            IncomingRequest incomingRequest,
            string clientId,
            RsaPrivateKey signingKey,
            RsaPrivateKey encryptionKey,
            OpenIdRequestSource requestSource,
            string redirectUri,
            Acr acr,
            int? maxAge,
            ServiceLocator serviceLocator
        )
        : base(
            incomingRequest,
            clientId,
            signingKey,
            encryptionKey,
            requestSource,
            redirectUri,
            acr,
            maxAge,
            serviceLocator
        )
        { }

        string BuildRequestUrl()
        {
            mServiceLocator.SessionDataHandler.RemoveAllGoodIdVariables();

            var iss = mIncomingRequest.GetStringParameter("iss");
            var configIssuerUri = mServiceLocator.ServerConfig.IssuerUri;
            if (string.IsNullOrEmpty(iss) || iss != configIssuerUri)
            {
                mServiceLocator.Logger.Log(Logger.Level.ERROR, iss);
                throw new GoodIdException("Iss parameter is missing or is not " + configIssuerUri);
            }

            var loginHint = mIncomingRequest.GetStringParameter("login_hint") ?? "";

            var extJson = mIncomingRequest.GetStringParameter("ext") ?? "";

            JObject ext;

            if (string.IsNullOrEmpty(extJson) != true)
            {
                ext = JObject.Parse(extJson);
            }
            else
            {
                ext = new JObject();
            }
            ext["sdk_version"] = Config.GOODID_SDK_VERSION;
            ext["profile_version"] = Config.GOODID_PROFILE_VERSION;


            var display = mIncomingRequest.GetStringParameter("display");

            if (string.IsNullOrEmpty(display))
            {
                throw new GoodIdException("Request parameter display missing or empty.");
            }

            // Empty value allowed
            var uiLocales = mIncomingRequest.GetStringParameter("ui_locales") ?? "";

            var queryParams = new Dictionary<string, string>
            {
                {"response_type", OpenIdRequestSource.RESPONSE_TYPE_CODE},
                {"client_id", mClientId},
                {"scope", OpenIdRequestSource.SCOPE_OPENID},
                {"state", mServiceLocator.StateNonceHandler.GenerateState()},
                {"nonce", mServiceLocator.StateNonceHandler.GenerateNonce()},
                {"ui_locales", uiLocales},
                {"ext",  Base64Url.Encode(System.Text.Encoding.UTF8.GetBytes(ext.ToString(Formatting.None)))}
            };

            if (string.IsNullOrEmpty(loginHint) != true)
            {
                queryParams["login_hint"] = loginHint;
            }

            var sessionDataHandler = mServiceLocator.SessionDataHandler;

            sessionDataHandler.SetVariable(SessionDataHandler.SESSION_KEY_APP_INITIATED, false);
            sessionDataHandler.SetVariable(SessionDataHandler.SESSION_KEY_USED_REDIRECT_URI, mRedirectUri);


            if (mRequestSource is OpenIdRequestUri openIdRequestUri)
            {
                queryParams["request_uri"] = openIdRequestUri.RequestUri;
                sessionDataHandler.SetVariable(SessionDataHandler.SESSION_KEY_REQUEST_SOURCE, openIdRequestUri.RequestUri);
            }
            else if (mRequestSource is OpenIdRequestObject openIdRequestObject)
            {
                var requestObjectJson = openIdRequestObject.ToJson(mClientId, mRedirectUri, mServiceLocator.ServerConfig, mAcr);
                queryParams["request"] = mSigningKey.SignAsCompactJws(requestObjectJson);
                sessionDataHandler.SetVariableRawJson(SessionDataHandler.SESSION_KEY_REQUEST_SOURCE, requestObjectJson);
            }
            else if (mRequestSource is OpenIdRequestObjectJwt openIdRequestObjectJwt)
            {
                queryParams["request"] = openIdRequestObjectJwt.Jwt;
                sessionDataHandler.SetVariableRawJson(SessionDataHandler.SESSION_KEY_REQUEST_SOURCE, openIdRequestObjectJwt.ToJson(mSigningKey));
            }
            else
            {
                throw new GoodIdException("Unsupported OpenIDRequestSource");
            }

            return mServiceLocator.ServerConfig.AuthorizationEndpointUri + "?" + Util.BuildHttpQuery(queryParams);
        }

        public override GoodIdHttpResponse Run()
        {
            var requestUrl = BuildRequestUrl();

            if (mIncomingRequest.GetMethod() == IncomingRequest.Method.GET)
            {
                return new GoodIdHttpResponseRedirect(requestUrl);
            }
            else
            {
                throw new GoodIdException("Unsupported http request method: " + mIncomingRequest.GetMethod());
            }
        }
    }
}
