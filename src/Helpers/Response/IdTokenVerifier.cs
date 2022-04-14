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
using GoodId.Core.Helpers.ClaimChecker;
using Newtonsoft.Json.Linq;

namespace GoodId.Core.Helpers.Response
{
    public class IdTokenVerifier
    {
        ClaimCheckerManager checkerManager;
        JObject idToken;
        public IdTokenVerifier(JObject idToken, string issuerUri, string clientId, int? requestedMaxAge, bool authTimeRequested, string nonce)
        {
            var timeToleranceInSeconds = 0;
            this.idToken = idToken;
            checkerManager = new ClaimCheckerManager();

            // OpenID specific validation
            checkerManager.Add(new IssuerChecker(issuerUri), true);
            checkerManager.Add(new AudienceChecker(clientId),true);
            checkerManager.Add(new SubChecker(),true);
            checkerManager.Add(new ExpirationChecker(timeToleranceInSeconds),true);
            checkerManager.Add(new IssuedAtChecker(timeToleranceInSeconds), true);
            checkerManager.Add(new AuthTimeChecker(timeToleranceInSeconds, requestedMaxAge ?? 0, authTimeRequested), authTimeRequested);
            checkerManager.Add(new NonceChecker(nonce));

            // GoodID specific validation
            Acr? acr;
            
            if((acr = idToken["acr"].ToObject<Acr?>())  == null)
            {
                acr = Acr.LEVEL_DEFAULT;
            }           
            checkerManager.Add(new GoodIDAcrChecker());
            checkerManager.Add(new GoodIDAppUserChecker(this.idToken), (acr >= Acr.LEVEL_3));
            checkerManager.Add(new GoodIDAppSealChecker(this.idToken), (acr >= Acr.LEVEL_4));
            checkerManager.Add(new GoodIDSignaturesChecker(this.idToken));

            checkerManager.Add(new GoodIDEmailHashExistenceChecker(), true);
            checkerManager.Add(new GoodIDUihExsistenceChecker(),true);


        }

        /**
         * 
         */
        public void Verify()
        {
            checkerManager.Check(idToken);
        }
    }
}