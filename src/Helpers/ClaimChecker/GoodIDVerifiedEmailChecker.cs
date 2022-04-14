using GoodId.Core.Exceptions;
using Jose;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
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
using System.Text;

namespace GoodId.Core.Helpers.ClaimChecker
{
    class GoodIDVerifiedEmailChecker : IClaimChecker
    {
        private const string ClaimName = "email";

        private string emailHash;

        public GoodIDVerifiedEmailChecker(string emailHash)
        {
            this.emailHash = emailHash;
        }

        public void CheckClaim(JToken token)
        {
            string email = token.Value<string>();

            using(SHA256 sha256Hash = SHA256.Create())
            {
                var emailHashInBytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(email));
                if (emailHash.Equals(Base64Url.Encode(emailHashInBytes)) == false)
                {
                    throw new ValidationException("Unverified email");
                }
            }   
        }

        public string SupportedClaim()
        {
            return ClaimName;
        }
    }
}
