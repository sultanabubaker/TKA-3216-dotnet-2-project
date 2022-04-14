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
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace GoodId.Core.Helpers
{
    public class GoodIdServerConfig
    {
        public virtual String IssuerUri
        {
            get { return "https://goodid.net"; }
        }

        public virtual String IdpUri
        {
            get { return "https://idp.goodid.net"; }
        }

        public virtual String AudienceUri
        {
            get { return IdpUri + "/"; }
        }

        public virtual String AuthorizationEndpointUri
        {
            get { return IdpUri + "/oidc/authorize"; }
        }

        public virtual String FastAuthorizationEndpointUri
        {
            get { return IdpUri + "/fast/authorize"; }
        }

        public virtual String TokenEndpointUri
        {
            get { return IdpUri + "/oidc/token"; }
        }

        public virtual String UserinfoEndpointUri
        {
            get { return IdpUri + "/oidc/userinfo"; }
        }

        public virtual String RemoteLoggingEndpointUri
        {
            get { return IdpUri + "/oidc/client-log-sink"; }
        }

        public virtual String JwksUri
        {
            get { return IdpUri + "/jwks.json"; }
        }

        private List<JObject> keyStore;

        public virtual List<JObject> KeyStore
        {
            get {
                if (keyStore is null)
                {
                    keyStore = new List<JObject>();
                    using (var client = new HttpClient())
                    {
                        var request = new HttpRequestMessage(HttpMethod.Get, JwksUri);
                        var response = client.SendAsync(request);
                        string jsonResult = response.Result.Content.ReadAsStringAsync().Result;
                        JObject keys = JObject.Parse(jsonResult);
                        if (keys["keys"] != null)
                        {
                            foreach (JObject key in keys["keys"])
                            {
                                keyStore.Add(key);
                            }
                        }  
                    }
                }
                return keyStore;
            }
        }

    }
}
