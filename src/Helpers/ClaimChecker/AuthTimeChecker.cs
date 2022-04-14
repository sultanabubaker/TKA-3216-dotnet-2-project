using GoodId.Core.Exceptions;
using Newtonsoft.Json.Linq;
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
using System;

namespace GoodId.Core.Helpers.ClaimChecker
{
    public class AuthTimeChecker : IClaimChecker
    {
        private const string ClaimName = "auth_time";

        private int timeToleranceInSeconds;
        private int requestedMaxAge;
        private bool  authTimeRequested;
        public AuthTimeChecker(int timeToleranceInSeconds, int requestedMaxAge = 0, bool authTmeRequested=false)
        {
            if (timeToleranceInSeconds < 0)
            {
                throw new ValidationException("Tolerance must be a non-negative number");
            }
            this.timeToleranceInSeconds = timeToleranceInSeconds;
            this.requestedMaxAge = requestedMaxAge;
            this.authTimeRequested = authTmeRequested;
        }

        public void CheckClaim(JToken token)
        {
            if (authTimeRequested)
            {

                long milliseconds = (long)token;
                DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
                dtDateTime = dtDateTime.AddSeconds(milliseconds).ToLocalTime();
                DateTimeOffset offset = dtDateTime;
                var authTime = offset.UtcDateTime;

                if (authTime.AddSeconds((-1 * timeToleranceInSeconds)).CompareTo(DateTime.UtcNow) > 0)
                {
                    throw new ValidationException("The user was authenticated in the future");
                }

                var timeDiff = DateTime.UtcNow.Subtract(authTime);
                if (timeDiff.TotalSeconds > (requestedMaxAge + timeToleranceInSeconds))
                {
                    throw new ValidationException("The user was authenticated too far in the past");
                }
            }
                    
        }

        public string SupportedClaim()
        {
            return ClaimName;
        }
    }
}
