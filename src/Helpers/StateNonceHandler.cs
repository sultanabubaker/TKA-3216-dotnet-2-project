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
using GoodId.Core.AbstractClasses;
using GoodId.Core.Exceptions;

namespace GoodId.Core.Helpers
{
    public class StateNonceHandler
    {
        /**
         * Length of a normal nonce
         * About 16 bytes entropy (in "base62")
         */
        const int NORMAL_NONCE_LENGTH = 22;

        readonly SessionDataHandler sessionDataHandler;
        readonly RandomStringGenerator randomStringGenerator;

        internal StateNonceHandler(SessionDataHandler sessionDataHandler, RandomStringGenerator randomStringGenerator)
        {
            this.sessionDataHandler = sessionDataHandler;
            this.randomStringGenerator = randomStringGenerator;
        }

        internal string GenerateState()
        {
            var state = randomStringGenerator.GetPseudoRandomString(NORMAL_NONCE_LENGTH);
            sessionDataHandler.SetVariable(SessionDataHandler.SESSION_KEY_STATE, state);

            return state;
        }

        internal bool ValidateState(string receivedState)
        {
            var storedState = getCurrentState();
            sessionDataHandler.RemoveVariable(SessionDataHandler.SESSION_KEY_STATE);

            return !string.IsNullOrEmpty(storedState) && receivedState == storedState;
        }

        internal string GenerateNonce()
        {
            var nonce = randomStringGenerator.GetPseudoRandomString(NORMAL_NONCE_LENGTH);
            sessionDataHandler.SetVariable(SessionDataHandler.SESSION_KEY_NONCE, nonce);

            return nonce;
        }

        internal bool ValidateNonce(string receivedNonce, string clientSecret, long currentGoodIDTime, long issuedAtTime)
        {
            if (receivedNonce == null)
            {
                throw new GoodIdException($"{nameof(receivedNonce)} is null");
            }

            var storedNonce = getCurrentNonce();

            sessionDataHandler.RemoveVariable(SessionDataHandler.SESSION_KEY_NONCE);

            if (receivedNonce.Length == NORMAL_NONCE_LENGTH)
            {
                return !string.IsNullOrEmpty(storedNonce) && receivedNonce == storedNonce;
            }
            throw new ValidationException("The nonce has invalid length");
        }
        public string getCurrentNonce()
        {
            return sessionDataHandler.GetVariableString(SessionDataHandler.SESSION_KEY_NONCE); ;
        }

        public string getCurrentState()
        {
            return sessionDataHandler.GetVariableString(SessionDataHandler.SESSION_KEY_STATE); ;
        }

        public void clear()
        {
            sessionDataHandler.RemoveVariable(SessionDataHandler.SESSION_KEY_STATE);
            sessionDataHandler.RemoveVariable(SessionDataHandler.SESSION_KEY_NONCE);
        }
    }
}
