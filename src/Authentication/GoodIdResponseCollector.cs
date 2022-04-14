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
using System.Threading.Tasks;
using GoodId.Core.AbstractClasses;
using GoodId.Core.Authentication.Response;
using GoodId.Core.Exceptions;
using GoodId.Core.Helpers.Key;
using GoodId.Core.Helpers.OpenIdRequestSources;
using GoodId.Core.Helpers.Response;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace GoodId.Core.Authentication
{
    public class GoodIdResponseCollector
    {
        ServiceLocator mServiceLocator;
        IncomingRequest mIncomingRequest;
        string mClientId;
        string mClientSecret;
        RsaPrivateKey mSigningKey;
        RsaPrivateKey[] mEncryptionKeys;
        bool mMatchingResponseValidation;

        public GoodIdResponseCollector(
             ServiceLocator serviceLocator,
             IncomingRequest incomingRequest,
             string clientId,
             string clientSecret,
             RsaPrivateKey signingKey,
             RsaPrivateKey[] encryptionKeys,
             bool matchingResponseValidation = true)
        {
            mServiceLocator = serviceLocator;
            mIncomingRequest = incomingRequest;
            mClientId = clientId;
            mClientSecret = clientSecret;
            mSigningKey = signingKey;
            mEncryptionKeys = encryptionKeys;
            mMatchingResponseValidation = matchingResponseValidation;
        }

        public async Task<GoodIdResponse> CollectAsync()
        {
            var sessionDataHandler = mServiceLocator.SessionDataHandler;
            var stateNonceHandler = mServiceLocator.StateNonceHandler;
            try
            {
                var goodIdServerConfig = mServiceLocator.ServerConfig;
                var requestFactory = mServiceLocator.RequestFactory;

                var method = mIncomingRequest.GetMethod();

                // Check HTTP method - Only HTTP GET acceptable when OP retun to the RP
                if (method != IncomingRequest.Method.GET)
                {
                    throw new GoodIdException($"Unexpected request method {method}!");
                }

                if (!stateNonceHandler.ValidateState(mIncomingRequest.GetStringParameter("state")))
                {
                    throw new ValidationException("The received state is invalid.");
                }

                var authCode = mIncomingRequest.GetStringParameter("code");

                // Handle error case
                if (string.IsNullOrEmpty(authCode))
                {
                    var error = mIncomingRequest.GetStringParameter("error");

                    if (string.IsNullOrEmpty(error))
                    {
                        throw new GoodIdException("Neither code nor error parameter is set.");
                    }

                    var errorDescription = mIncomingRequest.GetStringParameter("error_description");

                    return new GoodIdResponseError(error, errorDescription);
                }

                // Session parameters
                var requestSourceJson = sessionDataHandler.GetVariableRawJson(SessionDataHandler.SESSION_KEY_REQUEST_SOURCE);
                var usedRedirectUri = sessionDataHandler.GetVariableString(SessionDataHandler.SESSION_KEY_USED_REDIRECT_URI);

                if (string.IsNullOrEmpty(requestSourceJson))
                {
                    throw new GoodIdException("Request source is not set in session!");
                }

                if (string.IsNullOrEmpty(usedRedirectUri))
                {
                    throw new GoodIdException("Redirect uri is not set in session!");
                }


                var tokenResponse = await requestFactory.CreateTokenRequest(
                    goodIdServerConfig,
                    mServiceLocator.Logger,
                    mClientId,
                    mClientSecret,
                    usedRedirectUri,
                    authCode,
                    null
                ).ExecuteAsync();

                var jwe = tokenResponse.IdTokenJwe;

                var requestJObject = await GetRequestJObjectAsync(requestSourceJson, mSigningKey);
                int? requestedMaxAge = requestJObject?["max_age"] != null
                    ? (int?)requestJObject["max_age"]
                    : null;

                var authTimeRequested = false;

                if (requestJObject["claims"] != null && requestJObject["claims"]["id_token"] != null && requestJObject["claims"]["id_token"]["auth_time"] != null && requestJObject["claims"]["id_token"]["auth_time"]["essential"] != null)
                {
                    authTimeRequested |= (requestJObject["claims"]["id_token"]["auth_time"]["essential"].ToObject<bool>()) == true;
                }
                if (requestJObject["claims"] != null && requestJObject["claims"]["userinfo"] != null && requestJObject["claims"]["userinfo"]["auth_time"] != null && requestJObject["claims"]["userinfo"]["auth_time"]["essential"] != null)
                {
                    authTimeRequested |= (requestJObject["claims"]["userinfo"]["auth_time"]["essential"].ToObject<bool>()) == true;
                }

                TokenExtractor tokenExtractor = mServiceLocator.GetTokenExtractor(mEncryptionKeys);
                JObject idToken = tokenExtractor.ExtractToken(jwe);

                var idTokenVerifier = mServiceLocator.getIdTokenVerifier(
                                idToken,
                                mClientId,
                                requestedMaxAge,
                                authTimeRequested,
                                stateNonceHandler.getCurrentNonce()                );
                idTokenVerifier.Verify();

                if (tokenResponse.AccessToken != null)
                {
                    var accessToken = tokenResponse.AccessToken;

                    var userinfoResponse = await requestFactory.CreateUserinfoRequest(
                        goodIdServerConfig,
                        accessToken
                    ).ExecuteAsync();

                    JObject userinfo = tokenExtractor.ExtractToken(userinfoResponse.UserinfoJwe);

                    var userinfoVerifier = mServiceLocator.GetUserinfoVerifier(idToken, userinfo);
                    userinfoVerifier.Verify();

                    //TODO: matching validation
                    var validator = mServiceLocator.ResponseValidator;
                    validator.ValidateTokensBelongTogether(idToken, userinfo);
                    if (mMatchingResponseValidation)
                    {
                        if (requestJObject != null && requestJObject["claims"] != null && requestJObject["claims"].Type == JTokenType.Object)
                        {
                            validator.ValidateMatchingResponse((JObject)requestJObject["claims"], userinfo);
                        }
                        else
                        {
                            throw new ValidationException("Matching response validation cannot succeed because the request object was probably encrypted, or nothing was requested.");
                        }
                    }

                    var combined = MergeTokens(idToken, userinfo);

                    return new GoodIdResponseSuccess(accessToken, combined);

                }
                else
                {
                    throw new GoodIdException("You don't have access token.");
                }

            }
            catch (GoodIdException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new GoodIdException("Unknown error: " + e);
            }
            finally
            {
                sessionDataHandler.RemoveAllGoodIdVariables();
            }
        }

        async Task<JObject> GetRequestJObjectAsync(string requestSource, RsaPrivateKey signingKey)
        {
            try
            {
                return JObject.Parse(requestSource);
            }
            catch (JsonReaderException)
            {
                // It wasn't object, no problem
            }

            try
            {
                var requestUri = (string)JToken.Parse(requestSource);
                if (requestUri != OpenIdRequestSource.CONTENT_IS_ENCRYPTED)
                {
                    var downloadedRequestSource = await new OpenIdRequestUri(requestUri).ToJsonAsync(signingKey);

                    var jToken = JToken.Parse(downloadedRequestSource);

                    if (jToken.Type == JTokenType.Object)
                    {
                        return (JObject)jToken;
                    }

                    if (jToken.Type != JTokenType.String || (string)jToken != OpenIdRequestSource.CONTENT_IS_ENCRYPTED)
                    {
                        throw new Exception();
                    }
                }
            }
            catch (Exception)
            {
                throw new GoodIdException($"invalid {nameof(requestSource)}");
            }

            return null;
        }



        JObject MergeTokens(JObject idToken, JObject userinfo)
        {
            string[] userinfoStandardClaims = {
                "iss",
                "sub",
                "aud"
            };

            var combined = (JObject)idToken.DeepClone();
            var adaptedUserinfo = (JObject)userinfo.DeepClone();
            var userinfoToBeMerged = new JObject();

            // Userinfo has claims claim, 
            if (adaptedUserinfo["claims"] != null)
            {
                userinfoToBeMerged.Add("claims", adaptedUserinfo["claims"]);
            }
            // user info has no "claims" claim
            else
            {
                // remove the standard fields - they should not appear inside the claims
                foreach (var standardClaim in userinfoStandardClaims)
                {
                    adaptedUserinfo.Remove(standardClaim);
                }
                // move all of the cliams under a "claims" key
                userinfoToBeMerged.Add("claims", adaptedUserinfo);
            }

            // Combine the ID Token and the Userinfo into one token. 
            combined.Merge(userinfoToBeMerged, new JsonMergeSettings
            {
                // union array values together to avoid duplicates
                MergeArrayHandling = MergeArrayHandling.Union
            });

            return combined;
        }
    }
}