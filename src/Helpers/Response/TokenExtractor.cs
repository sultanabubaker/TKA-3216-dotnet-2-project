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
using GoodId.Core.Helpers.Key;
using Jose;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace GoodId.Core.Helpers.Response
{
    public class TokenExtractor
    {

        RsaPrivateKey[] rpEncryptionKeys;        // Encryption keys
        List<JObject> signingKeys;                // JWKS - signing keys. Signing key can be an RSA or an EC key also.

        public TokenExtractor(RsaPrivateKey[] rpRSAKeys, List<JObject> signingKeys)
        {
            rpEncryptionKeys = rpRSAKeys;
            this.signingKeys = signingKeys;
        }


        public void VerifyServerSignatures(string jwsJson)
        {
            foreach (var jwk in signingKeys)
            {
                try
                {
                    Util.VerifyTokenSignature(jwsJson, jwk);
                    return;
                }
                catch (Exception)
                {
                    // No problm just trying with the next key
                    continue;
                }
            }
            throw new GoodIdException("JWS signature can't be verified");
        }

        public string Decrypt(string jweJson)
        {
            var exceptionMessages = "";

            foreach (var encryptionKey in rpEncryptionKeys)
            {
                try
                {

                    return encryptionKey.DecryptCompactJwe(jweJson);
                }
                catch (GoodIdException e)
                {
                    exceptionMessages += e + ", ";
                }
            }
            throw new GoodIdException("No key could decrypt: " + exceptionMessages);
        }

        public JObject ExtractToken(string jwtJson)
        {
            string jwsJson = "";
            if (Util.IsCompactJws(jwtJson))
            {
                jwsJson = jwtJson;
            }
            else if (Util.IsCompactJwe(jwtJson))
            {
                string decryptedJweJson = Decrypt(jwtJson);
                decryptedJweJson = decryptedJweJson.Trim();

                // If it is an ID token - payload still a JWT
                // If its a userinfo, the payload a JSON
                if ((decryptedJweJson.StartsWith("{") && decryptedJweJson.EndsWith("}")) || //For object
                    (decryptedJweJson.StartsWith("[") && decryptedJweJson.EndsWith("]"))) //For array
                {
                    // Maybe a valid JSON - try parse it!
                    try
                    {
                        return JObject.Parse(decryptedJweJson);
                    }
                    catch (JsonReaderException)
                    {
                        // Parsing exception -  its not a valid JSON. It may be a JWS
                        jwsJson = decryptedJweJson;
                    }
                }
                else
                {
                    // It's sure that is not a JSON  - it should be a JWS
                    jwsJson = decryptedJweJson;
                }
            }
            else
            {
                throw new GoodIdException("Unsupported input");
            }
            VerifyServerSignatures(jwsJson);
            return JObject.Parse(JWT.Payload(jwsJson));
        }

    }
}
