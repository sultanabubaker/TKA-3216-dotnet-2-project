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
using GoodId.Core.Authentication.Endpoint;
using GoodId.Core.Exceptions;
using GoodId.Core.Helpers;
using GoodId.Core.Helpers.Key;
using GoodId.Core.Helpers.OpenIdRequestSources;
using System;

namespace GoodId.Core.Authentication
{
    public static class GoodIdEndpointFactory
    {
        public static GoodIdEndpoint CreateGoodIDEndpoint(
            ServiceLocator serviceLocator,
            IncomingRequest incomingRequest,
            string clientId,
            RsaPrivateKey signingKey,
            RsaPrivateKey encryptionKey,
            OpenIdRequestSource openIdRequestSource,
            string redirectUri,
            Acr acr = Acr.LEVEL_DEFAULT,
            int? maxAge = null
        )
        {
            try
            {
                var goodIdServerConfig = serviceLocator.ServerConfig;
                
                var sessionDataHandler = serviceLocator.SessionDataHandler;
                var stateNonceHandler = serviceLocator.StateNonceHandler;

               
                return new GoodIdRequestBuilderEndpoint(
                    incomingRequest,
                    clientId,
                    signingKey,
                    encryptionKey,
                    openIdRequestSource,
                    redirectUri,
                    acr,
                    maxAge,
                    serviceLocator
                );
            }catch (GoodIdException){
                throw;
            }
            catch (Exception e){
                throw new GoodIdException("Unknown error: " + e.Message);
            }
        }
    }
}
