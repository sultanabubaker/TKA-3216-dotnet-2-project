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

namespace GoodId.Core.Helpers.OpenIdRequestSources
{
    public class OpenIdRequestObject : OpenIdRequestSource
    {
        readonly JObject mClaims;

        public OpenIdRequestObject(string claims)
        {
            try
            {
                mClaims = JObject.Parse(claims);
            }
            catch (Exception)
            {
                throw new GoodIdException($"{nameof(claims)} must be valid json");
            }

            if (mClaims["id_token"]?["acr"]?["value"] != null)
            {
                try
                {
                    Acr acr = (Acr)(int)mClaims["id_token"]["acr"]["value"];
                }
                catch (Exception)
                {
                    throw new GoodIdException("Acr must be a valid acr value");
                }
            }
        }

        public string ToJson(
            string clientId,
            string redirectUri,
            GoodIdServerConfig goodIdServerConfig,
            Acr acr = Acr.LEVEL_DEFAULT,
            int? maxAge = null
        )
        {
            AddAcr(acr);

            var obj = new JObject
            {
                ["iss"] = clientId,
                ["aud"] = goodIdServerConfig.AudienceUri,
                ["response_type"] = RESPONSE_TYPE_CODE,
                ["client_id"] = clientId,
                ["redirect_uri"] = redirectUri,
                ["scope"] = SCOPE_OPENID,
                ["claims"] = mClaims
            };

            if (maxAge.HasValue)
            {
                obj["max_age"] = maxAge.Value;
            }

            return obj.ToString(Newtonsoft.Json.Formatting.None);
        }

        void AddAcr(Acr acr)
        {
            if (mClaims["id_token"] == null)
            {
                mClaims["id_token"] = new JObject();
            }

            if (mClaims["id_token"]["acr"] == null)
            {
                mClaims["id_token"]["acr"] = new JObject();
            }

            if (mClaims["id_token"]["acr"]["value"] == null)
            {
                mClaims["id_token"]["acr"]["value"] = ((int)acr).ToString();
            }
            else
            {
                var oldAcr = (int)mClaims["id_token"]["acr"]["value"];

                // ACR value must be a string
                mClaims["id_token"]["acr"]["value"] = Math.Max(oldAcr, (int)acr).ToString();
            }
        }
    }
}
