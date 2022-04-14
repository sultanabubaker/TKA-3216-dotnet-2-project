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
namespace GoodId.Core.Helpers.ClaimChecker
{
    using GoodId.Core.Exceptions;
    using Newtonsoft.Json.Linq;
    using System.Collections.Generic;

    /**
         https://github.com/web-token/jwt-framework/blob/v2.0/src/Component/Checker/ClaimCheckerManager.php
     */
    public class ClaimCheckerManager {

        protected Dictionary<string, IClaimChecker> checkers;
        protected HashSet<string> mandatoryClaims;
        public ClaimCheckerManager () {
            checkers = new Dictionary<string, IClaimChecker> ();
            mandatoryClaims = new HashSet<string>();
        }

        /**
         * @return ClaimCheckerManager
         */
        public void Add (IClaimChecker checker, bool mandatory = false) {
            checkers[checker.SupportedClaim ()] = checker;
            if(mandatory == true)
            {
                mandatoryClaims.Add(checker.SupportedClaim());
            }
        }

        /**
         * This method returns all checkers handled by this manager.
         *
         * @return Dictionary<string, IClaimChecker>
         */
        public Dictionary<string, IClaimChecker> getCheckers () {
            return checkers;
        }

        /**
         * This method checks all the claims passed as argument.
         * All claims are checked against the claim checkers.
         * If one fails, the InvalidClaimException is thrown.
         *
         * This method returns an array with all checked claims.
         * It is up to the implementor to decide use the claims that have not been checked.     
         */
        public Dictionary<string, object> Check (JObject jObject) {
            IDictionary<string, JToken> claims = jObject;
            //TODO: Mandatory claims
            Dictionary<string, object> checkedClaims = new Dictionary<string, object> ();

            foreach (KeyValuePair<string, IClaimChecker> entry in checkers) {
                if (claims.ContainsKey (entry.Key) == true) {
                    var checker = entry.Value;

                    checker.CheckClaim (claims[entry.Key]);
                    checkedClaims[entry.Key] = claims[entry.Key];
                }
                else if (mandatoryClaims.Contains(entry.Key))
                {
                    throw new GoodIdException($"Mandatory claim [{entry.Key}] is not provided");
                }
            }
            return checkedClaims;
        }

    }

}