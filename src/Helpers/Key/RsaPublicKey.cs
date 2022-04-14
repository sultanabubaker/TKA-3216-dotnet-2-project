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
using System;
using System.Security.Cryptography;
using System.Text;

namespace GoodId.Core.Helpers.Key
{
    public class RsaPublicKey
    {
        protected enum KeyFormat
        {
            PEM,
            JWK
        }

        protected RSA mKey;
        protected bool mHasPrivateParameters;

        protected RsaPublicKey(string key, KeyFormat format)
        {
            switch (format)
            {
                case KeyFormat.PEM:
                    var RSAParameters = Converters.PemToRsaParameters(key, out mHasPrivateParameters);
                    mKey = RSA.Create();
                    mKey.ImportParameters(RSAParameters);

                    break;
                default:
                    throw new GoodIdException("Unsupported key format");
            }
        }

        public static RsaPublicKey FromPem(string pem)
        {
            return new RsaPublicKey(pem, KeyFormat.PEM);
        }

        internal string VerifyCompactJws(string compactJws)
        {
            try
            {
                return JWT.Decode(compactJws, mKey, JwsAlgorithm.RS256);
            }
            catch (Exception e)
            {
                throw new GoodIdException("Can not verify signature: " + e);
            }
        }

        internal string EncryptAsCompactJwe(string payload)
        {
            return JWT.Encode(payload, mKey, JweAlgorithm.RSA_OAEP, JweEncryption.A256CBC_HS512);
        }

        internal string GetKid()
        {
            RSAParameters parameters = mKey.ExportParameters(false);
            return Thumbprint("RSA", Base64Url.Encode(parameters.Exponent), Base64Url.Encode(parameters.Modulus)).Substring(0, 5);
        }

        string Thumbprint(string kty, string e, string n)
        {
            return Base64Url.Encode(Util.Sha256Hash(Encoding.ASCII.GetBytes(
                $"{{\"e\":\"{e}\",\"kty\":\"{kty}\",\"n\":\"{n}\"}}")));
        }
    }
}
