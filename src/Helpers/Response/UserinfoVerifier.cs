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
using GoodId.Core.Helpers.ClaimChecker;
using Jose;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Text;

namespace GoodId.Core.Helpers.Response
{
    public class UserinfoVerifier
    {
        ClaimCheckerManager checkerManager;


        private JObject idToken;
        private JObject userinfo;

        public UserinfoVerifier(JObject idToken, JObject userinfo)
        {
            this.idToken = idToken;
            this.userinfo = userinfo;

            checkerManager = new ClaimCheckerManager();
            // OpenID specific validation
            checkerManager.Add(new SubChecker(idToken["sub"].ToObject<string>()), true);

            // GoodID specific validation
            checkerManager.Add(new GoodIDVerifiedEmailChecker(idToken["email_hash"].ToObject<string>()));

        }
        public void Verify()
        {
            //Check userinfo hash
            var normalisedUserInfo = Util.NormalizeJson(userinfo);
            var userinfoHash = Base64Url.Encode(Util.Sha256Hash(Encoding.UTF8.GetBytes(normalisedUserInfo.ToString(Formatting.None))));
            var expectedUserinfoHash = idToken["uih"].ToObject<string>();

            if (userinfoHash.Equals(expectedUserinfoHash) == false)
            {
                throw new ValidationException("Unverified userinfo");
            }
            // Check userinfo's claims
            checkerManager.Check(userinfo);
        }
    }


}
