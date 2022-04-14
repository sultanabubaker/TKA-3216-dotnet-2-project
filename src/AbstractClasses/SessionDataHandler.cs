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
using GoodId.Core.Helpers;
using Newtonsoft.Json.Linq;

namespace GoodId.Core.AbstractClasses
{
    public abstract class SessionDataHandler
    {
        /**
         *
         * The session key for nonce
         * Value type: string
         */
        internal const string SESSION_KEY_NONCE = "nonce";

        /**
         * The session key for state
         * Value type: string
         */
        internal const string SESSION_KEY_STATE = "state";

        /**
         * The session key for the used redirect_uri
         * Value type: string
         */
        internal const string SESSION_KEY_USED_REDIRECT_URI = "redirecturi";

        /**
         * The session key for:
         *     Request object as array, or request uri as string, or OpenIDRequestSource::CONTENT_IS_ENCRYPTED
         * Value type: string|JObject
         */
        internal const string SESSION_KEY_REQUEST_SOURCE = "reqsource";

        /**
         * Session key: Is the request initiated outside the RP backend.
         * Eg.: provider screen
         * Value type: bool
         */
        internal const string SESSION_KEY_APP_INITIATED = "appinit";

        internal void SetVariable(string key, string value)
        {
            SetVariableImpl(key, Util.Jsonize(value));
        }

        internal void SetVariable(string key, bool value)
        {
            SetVariableImpl(key, Util.Jsonize(value));
        }

        internal string GetVariableString(string key)
        {
            var s = GetVariableImpl(key);
            return s != null ? (string)JToken.Parse(s) : null;
        }

        internal bool? GetVariableOptBool(string key)
        {
            var s = GetVariableImpl(key);
            return s != null ? (bool?)JToken.Parse(s) : null;
        }

        internal void SetVariableRawJson(string key, string jsonStringValue)
        {
            SetVariableImpl(key, jsonStringValue);
        }

        internal string GetVariableRawJson(string key)
        {
            return GetVariableImpl(key);
        }

        internal void RemoveVariable(string key)
        {
            RemoveVariableImpl(key);
        }

        internal void RemoveAllGoodIdVariables()
        {
            RemoveAllGoodIdVariablesImpl();
        }


		// Please return null if not found.
		protected abstract string GetVariableImpl(string key);
        protected abstract void SetVariableImpl(string key, string value);
        protected abstract void RemoveVariableImpl(string key);
        protected abstract void RemoveAllGoodIdVariablesImpl();
    }
}
