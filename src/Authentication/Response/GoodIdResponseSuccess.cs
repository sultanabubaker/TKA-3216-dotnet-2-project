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
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace GoodId.Core.Authentication.Response
{
    public class GoodIdResponseSuccess : GoodIdResponse
    {
        readonly string mAccessToken;
        public string AccessToken
        {
            get { return mAccessToken; }
        }

        readonly string mDataJson;
        public string DataJson
        {
            get { return mDataJson; }
        }

        readonly string mClaimsJson;
        public string ClaimsJson
        {
            get { return mClaimsJson; }
        }

        readonly JObject mDataJObject;
        public JObject DataJObject
        {
            get { return mDataJObject; }
        }

        readonly JObject mClaimsJObject;
        public JObject ClaimsJObject
        {
            get { return mClaimsJObject; }
        }

        readonly string mSub;
        public string Sub
        {
            get { return mSub; }
        }

        internal GoodIdResponseSuccess(string accessToken, JObject dataJObject)
        {
            mAccessToken = accessToken;
            mDataJson = dataJObject.ToString(Formatting.None);
            if( !(dataJObject["claims"] is null))
            {
                mClaimsJson = dataJObject["claims"].ToString(Formatting.None);
                mDataJObject = dataJObject;
                mClaimsJObject = (JObject)dataJObject["claims"].DeepClone();
            }           
            mSub = (string)dataJObject["sub"];
        }
    }
}
