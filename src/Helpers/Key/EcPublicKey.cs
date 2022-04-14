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
using Jose;
using Newtonsoft.Json.Linq;
using System;
using System.Security.Cryptography;
using System.Text;

namespace GoodId.Core.Helpers.Key
{
    /**
     * An elliptic curve cryptography key class
     * Only a limited functionality is implemented, just what we need
     */
    class EcPublicKey
    {
        /**
         * Elliptic curve key type
         */
        const string KEY_TYPE_EC = "EC";

        /**
         * P-256 curve
         */
        const string CURVE_P256 = "P-256";

        /**
         * SHA256 jwk thumbprint type
         */
        const string JWK_THUMBPRINT_TYPE_SHA_256 = "sha256";

        static string Thumbprint(string crv, string kty, string x, string y)
        {
            return Base64Url.Encode(Util.Sha256Hash(Encoding.ASCII.GetBytes(
                $"{{\"crv\":\"{crv}\",\"kty\":\"{kty}\",\"x\":\"{x}\",\"y\":\"{y}\"}}")));
        }

#if (NETCOREAPP2_1 || NETSTANDARD2_0)
        static ECDsa CreatePublicKey(ECCurve curve, byte[] x, byte[] y)
        {

            return ECDsa.Create(new ECParameters
            {
                Curve = curve,
                Q = new ECPoint
                {
                    X = x,
                    Y = y
                },
                D = null
            });
        }
#endif

        internal static string VerifySelfSignedCompactJws(string compactJws)
        {
            JObject payload;

            try
            {
                payload = JObject.Parse(JWT.Payload(compactJws));
            }
            catch (Exception)
            {
                throw new GoodIdException("Invalid JWS string.");
            }

            var subJwk = payload["sub_jwk"];
            if (subJwk == null)
            {
                throw new GoodIdException("Missing sub_jwk.");
            }

            string x, y;
#if (NETCOREAPP2_1 || NETSTANDARD2_0)
            ECDsa key;
#else
            CngKey key;
#endif
            try
            {
                x = (string)subJwk["x"];
                y = (string)subJwk["y"];

#if (NETCOREAPP2_1 || NETSTANDARD2_0)
                key = CreatePublicKey(ECCurve.NamedCurves.nistP256, Base64Url.Decode(x), Base64Url.Decode(y));
#else
                key = Security.Cryptography.EccKey.New(Base64Url.Decode(x), Base64Url.Decode(y));
#endif
            }
            catch (Exception)
            {
                throw new GoodIdException("Invalid sub_jwk format.");
            }

            var sub = payload["sub"];
            if (sub == null)
            {
                throw new GoodIdException("Missing sub.");
            }

            var thumbprint = Thumbprint(EcPublicKey.CURVE_P256, EcPublicKey.KEY_TYPE_EC, x, y);
            if (sub == null || thumbprint != (string)sub)
            {
                throw new GoodIdException("Invalid signature: sub vs sub_jwk mismatch.");
            }

            try
            {
                return JWT.Decode(compactJws, key);
            }
            catch (Exception)
            {
                throw new GoodIdException("Invalid signature.");
            }
        }
    }
}
