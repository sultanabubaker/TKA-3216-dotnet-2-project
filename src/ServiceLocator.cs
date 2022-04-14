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
using GoodId.Core.Helpers;
using GoodId.Core.Helpers.Key;
using GoodId.Core.Helpers.Request;
using GoodId.Core.Helpers.Response;
using Newtonsoft.Json.Linq;

namespace GoodId.Core
{
    public class ServiceLocator
    {
        GoodIdServerConfig serverConfig;

        public GoodIdServerConfig ServerConfig
        {
            get
            {
                if (serverConfig == null)
                {
                    serverConfig = CreateServerConfig();
                }
                return serverConfig;
            }
            set
            {
                serverConfig = value;
            }
        }

        protected virtual GoodIdServerConfig CreateServerConfig()
        {
            return new GoodIdServerConfig();
        }

        SessionDataHandler sessionDataHandler;

        public SessionDataHandler SessionDataHandler
        {
            get { return sessionDataHandler; }
        }

        Logger logger;
        internal Logger Logger
        {
            get { return logger; }
        }

        RandomStringGenerator randomStringGenerator;

        public RandomStringGenerator RandomStringGenerator
        {
            get
            {
                if (randomStringGenerator == null)
                {
                    randomStringGenerator = CreateRandomStringGenerator();
                }
                return randomStringGenerator;
            }
        }

        protected virtual RandomStringGenerator CreateRandomStringGenerator()
        {
            return new RandomStringGenerator();
        }

        StateNonceHandler stateNonceHandler;

        public StateNonceHandler StateNonceHandler
        {
            get
            {
                if (stateNonceHandler == null)
                {
                    stateNonceHandler = CreateStateNonceHandler();
                }
                return stateNonceHandler;
            }
        }

        protected virtual StateNonceHandler CreateStateNonceHandler()
        {
            return new StateNonceHandler(SessionDataHandler, RandomStringGenerator);
        }

        ResponseValidator responseValidator;

        public ResponseValidator ResponseValidator
        {
            get
            {
                if (responseValidator == null)
                {
                    responseValidator = new ResponseValidator();
                }
                return responseValidator;
            }
        }


        RequestFactory requestFactory;

        public RequestFactory RequestFactory
        {
            get
            {
                if (requestFactory == null)
                {
                    requestFactory = CreateRequestFactory();
                }
                return requestFactory;
            }
        }

        protected virtual RequestFactory CreateRequestFactory()
        {
            return new RequestFactory();
        }

        public ServiceLocator(SessionDataHandler sessionDataHandler, Logger logger)
        {
            this.sessionDataHandler = sessionDataHandler;
            this.logger = logger;
        }

        public IdTokenVerifier getIdTokenVerifier(JObject idToken, string clientId, int? requestedMaxAge, bool authTimeRequested, string nonce)
        {
            return new IdTokenVerifier(
                idToken,
                this.serverConfig.IssuerUri,
                clientId,
                requestedMaxAge,
                authTimeRequested,
                nonce
            );
        }

        public TokenExtractor GetTokenExtractor(RsaPrivateKey[] rpRsaKeys)
        {
            var serverKeys = this.ServerConfig.KeyStore;
            return new TokenExtractor(rpRsaKeys, serverKeys);
        }

        public UserinfoVerifier GetUserinfoVerifier(JObject idToken, JObject userinfo)
        {
            return new UserinfoVerifier(idToken, userinfo);
        }

    }

}
