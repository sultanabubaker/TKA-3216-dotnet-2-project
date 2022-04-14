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
using Newtonsoft.Json.Linq;
using System;

namespace GoodId.Core.Helpers.Response
{
    public class ResponseValidator
    {   
        /// <summary>
        /// 
        /// 
        /// </summary>
        /// <param name="idToken"></param>
        /// <param name="userinfo"></param>
        internal void ValidateTokensBelongTogether(JObject idToken, JObject userinfo)
        {
            if (idToken["sub"] == null
               || userinfo["sub"] == null
               || (string)idToken["sub"] != (string)userinfo["sub"])
            {
                throw new ValidationException("The idToken and userinfo data belong to different users.");
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="requestedClaims"></param>
        /// <param name="userinfo"></param>
        internal void ValidateMatchingResponse(JObject requestedClaims, JObject userinfo)
        {
            if (requestedClaims["userinfo"] != null)
            {
                var requestedUserinfoClaims = (JObject)requestedClaims["userinfo"];
                var userinfoClaims = userinfo["claims"] != null
                    ? (JObject)userinfo["claims"]
                    : new JObject();
                ValidateMatchingResponseForToken(requestedUserinfoClaims, userinfoClaims);
            }
        }

      /// <summary>
      /// TODO!!!!!!
      /// </summary>
      /// <param name="request"></param>
      /// <param name="response"></param>
        void ValidateMatchingResponseForToken(JObject request, JObject response)
        {
            // TODO!!!
            return;
        }

        JToken GetClaimValue(JObject claims, string claimName)
        {
            string[] components = claimName.Split('.');

            JToken current = claims;

            foreach (string component in components)
            {
                if (current[component] != null)
                {
                    current = current[component];
                }
                else
                {
                    return null;
                }
            }

            return current;
        }

        bool GetBoolValue(JToken valueInRequest, string attribute, bool defaultValue)
        {
            if (valueInRequest.Type == JTokenType.Object
               && valueInRequest[attribute] != null)
            {
                return false;
            }

            return defaultValue;
        }

        bool IsVerificationClaim(string propertyName)
        {
            return propertyName.EndsWith("_verified", StringComparison.Ordinal);
        }
    }
}
