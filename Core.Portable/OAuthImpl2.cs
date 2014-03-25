using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace EasyOAuth.Core.Portable
{
    public abstract class OAuthImpl2 : OAuth
    {
        public event EventHandler<OAuthTokenReadyToRedirectEventArgs> ReadyRedirect;

        public string ClientKey { get; protected set; }
        public string ClientSecret { get; protected set; }
        public string Token { get; protected set; }
        public string Scope { get; protected set; }

        public OAuthImpl2(string ClientKey, string ClientSecret, string Scope)
        {
            this.ClientKey = ClientKey;
            this.ClientSecret = ClientSecret;
            this.Scope = Scope;
        }

        public OAuthImpl2(string ClientKey, string ClientSecret, string Scope, string Token)
            : this(ClientKey, ClientSecret, Scope)
        {
            this.Token = Token;
        }

        public abstract void RequestToken();
        public abstract void AccessToken(string LoginCallbackData);
        public abstract byte[] ConsumeService(Uri ServiceUri, string HttpMethod, byte[] Parameters);

        public void AccessToken(string Token, string Verifier)
        {
            throw new NotSupportedException(); // do not implement in OAuth 2.0
        }

        public void OnReadyRedirect(OAuthTokenReadyToRedirectEventArgs e)
        {
            if (this.ReadyRedirect != null)
                this.ReadyRedirect(this, e);
        }
    }
}
