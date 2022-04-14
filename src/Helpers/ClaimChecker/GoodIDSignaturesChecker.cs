using GoodId.Core.Exceptions;
using Jose;
using Newtonsoft.Json;
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
using Newtonsoft.Json.Linq;
using System;
using System.Text;

namespace GoodId.Core.Helpers.ClaimChecker
{
    public  class GoodIDSignaturesChecker : IClaimChecker
    {
        private const string CLAIM_NAME = "signatures";
        private JObject payload;

        public GoodIDSignaturesChecker(JObject idToken){

            payload = (JObject) idToken.DeepClone();
            payload.Remove("signatures");
            payload = Util.NormalizeJson(payload);

        }
        public void CheckClaim(JToken token){

            JArray signatures = (JArray)token;
            string payloadString  = Base64Url.Encode(Encoding.UTF8.GetBytes(payload.ToString(Formatting.None) ));

            foreach (JToken signature in signatures){
                var protectedPart = signature["protected"];
                var signaturePart = signature["signature"];

                var compactJWS = protectedPart + "." + payloadString + "." + signaturePart;

                var headers = JWT.Headers(compactJWS);

                // Get jwk and it's kid
                var jwk = JObject.FromObject( headers["jwk"]);
                string kid = jwk["kid"].ToString();

                // compute the actual key's thumbprint 
                string computedThumbprint = Base64Url.Encode(Util.Sha256Hash(Encoding.ASCII.GetBytes(
                $"{{\"crv\":\"{jwk["crv"]}\",\"kty\":\"{jwk["kty"]}\",\"x\":\"{jwk["x"]}\",\"y\":\"{jwk["y"]}\"}}")));

                // Based on the kid - check that recently computed thumbprint is matching with one of the sent in the claims
                var claimToCheck = kid.Substring(0, kid.Length - "_jwk".Length);
                if (payload[claimToCheck] == null)
                {
                    throw new ValidationException("Missing app signed claim");
                }
                if (payload[claimToCheck].ToString().Equals(computedThumbprint) == false)
                {
                    throw new ValidationException($"Bad signiture {claimToCheck}");
                }
                // - check the signature
                try
                {
                    Util.VerifyTokenSignature(compactJWS, jwk);
                }
                catch (Exception)
                {
                    throw new ValidationException("Invalid signatures");
                }
               
               
            }
        }
        public string SupportedClaim(){
            return CLAIM_NAME;
        }
    }
}