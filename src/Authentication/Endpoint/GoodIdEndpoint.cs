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
using GoodId.Core.Helpers;
using GoodId.Core.Helpers.HttpResponses;
using GoodId.Core.Helpers.Key;
using GoodId.Core.Helpers.OpenIdRequestSources;

namespace GoodId.Core.Authentication.Endpoint
{
    public abstract class GoodIdEndpoint
    {
        /**
        * The smallest accepted value for max_age
        */
        const int MAX_AGE_MIN_VALUE = 3600;

        /**
         * The largest accepted value for max_age
         * 60 days in seconds
         */
        const int MAX_AGE_MAX_VALUE = 5184000;

        protected IncomingRequest mIncomingRequest;
        protected string mClientId;
        protected RsaPrivateKey mSigningKey;
        protected RsaPrivateKey mEncryptionKey;
        protected OpenIdRequestSource mRequestSource;
        protected string mRedirectUri;
        protected Acr mAcr;
        protected int? mMaxAge;
        protected ServiceLocator mServiceLocator;

        protected GoodIdEndpoint(
            IncomingRequest incomingRequest,
            string clientId,
            RsaPrivateKey signingKey,
            RsaPrivateKey encryptionKey,
            OpenIdRequestSource requestSource,
            string redirectUri,
            Acr acr,
            int? maxAge,
            ServiceLocator serviceLocator)
        {
            if (string.IsNullOrEmpty(clientId))
            {
                throw new GoodIdException($"{nameof(clientId)} can not be empty");
            }

            if (maxAge.HasValue && (maxAge.Value < MAX_AGE_MIN_VALUE || maxAge.Value > MAX_AGE_MAX_VALUE))
            {
                throw new GoodIdException($"{nameof(maxAge)} must be null or an int in the range [{MAX_AGE_MIN_VALUE}, {MAX_AGE_MAX_VALUE}]");
            }

            mIncomingRequest = incomingRequest;
            mClientId = clientId;
            mSigningKey = signingKey;
            mEncryptionKey = encryptionKey;
            mRequestSource = requestSource;
            mRedirectUri = redirectUri;
            mAcr = acr;
            mMaxAge = maxAge;
            mServiceLocator = serviceLocator;
        }

        /**
         * This will run the main logic of the concrete endpoint
         */
        abstract public GoodIdHttpResponse Run();
    }
}
