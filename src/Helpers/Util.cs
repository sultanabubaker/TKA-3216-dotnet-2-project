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
using Jose;
using Newtonsoft.Json.Linq;
using Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace GoodId.Core.Helpers
{
    static class Util
    {
        internal static string Jsonize(string s)
        {
            return $"\"{s}\"";
        }

        internal static string Jsonize(bool b)
        {
            return b ? "true" : "false";
        }

        internal static bool IsCompactJws(string jwt)
        {
            return jwt.Count(c => c == '.') == 2;
        }

        internal static bool IsCompactJwe(string jwt)
        {
            return jwt.Count(c => c == '.') == 4;
        }

        internal static string BuildHttpQuery(Dictionary<String, String> queryParams)
        {
            return String.Join("&", queryParams.Select(
                kv => Uri.EscapeDataString(kv.Key) + "=" + Uri.EscapeDataString(kv.Value)));
        }

        internal static byte[] Sha256Hash(byte[] bytes)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(bytes);
            }
        }

        internal static void VerifyTokenSignature(string JwsJson, JObject jwk)
        {
            if ("EC".Equals(jwk["kty"].ToString()))
            {
                byte[] x = Base64Url.Decode(jwk["x"].ToString());
                byte[] y = Base64Url.Decode(jwk["y"].ToString());

#if (NETCOREAPP2_1 || NETSTANDARD2_0)
                var publicKey = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint
                    {
                        X = x,
                        Y = y
                    },
                    D = null
                });

                var decoded = JWT.Decode(JwsJson, publicKey);
#else
                CngKey cngKey = EccKey.New(x, y);
                var decoded = JWT.Decode(JwsJson, cngKey);
#endif
                return;
            }
            else if ("RSA".Equals(jwk["kty"].ToString()))
            {
                byte[] n = Base64Url.Decode(jwk["n"].ToString());
                byte[] e = Base64Url.Decode(jwk["e"].ToString());

                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {

                    RSAParameters rsaParameters = new RSAParameters
                    {
                        Exponent = e,
                        Modulus = n
                    };
                    RSA.ImportParameters(rsaParameters);
                    JWT.Decode(JwsJson, RSA);
                    return;
                }
                /*var publicKey = RsaKey.New(e, n);
                var decoded = JWT.Decode(JwsJson, publicKey);
                return;*/
            }
        }

        private static JObject SortJObject(JObject jObj)
        {
            return new JObject(
               jObj.Properties().OrderBy(p => (string)p.Name)
           );
        }

        /**

        /**
        * It sorts an JObject object by it's keys
        */
        internal static JObject NormalizeJson(JObject obj)
        {
            JObject o = SortJObject(obj);
            foreach (KeyValuePair<string, JToken> kvp in o)
            {
                var key = kvp.Key;
                var token = kvp.Value;
                if (token is JObject)
                {
                    o[key] = NormalizeJson((JObject)token);
                }
            }
            return o;
        }

    }
}
