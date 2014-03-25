using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace EasyOAuth.Core
{
    public abstract class OAuthImpl1a : OAuth
    {
        public event EventHandler<OAuthTokenEventArgs> BeforeRequestToken;
        public event EventHandler<OAuthTokenEventArgs> BeforeAccessToken;
        public event EventHandler<OAuthTokenEventArgs> BeforeConsumeService;
        public event EventHandler<OAuthTokenReadyToRedirectEventArgs> ReadyRedirect;
        public event EventHandler<OAuthCompletedEventArgs> Completed;

        public string ClientId { get; protected set; }
        public string ClientSecret { get; protected set; }
        public string Token { get; protected set; }
        public string TokenSecret { get; protected set; }

        private OAuthBaseStringBuilder _baseStringBuilder = null;
        private OAuthSignatureProvider _signatureProvider = null;
        private OAuthAuthorizationHeaderBuilder _authorizationHeaderBuilder = null;

        public OAuthImpl1a(string ClientKey, string ClientSecret)
        {
            this.ClientId = ClientKey;
            this.ClientSecret = ClientSecret;
        }

        public OAuthImpl1a(string ClientKey, string ClientSecret, string Token, string TokenSecret) 
            : this(ClientKey, ClientSecret)
        {
            this.Token = Token;
            this.TokenSecret = TokenSecret;
        }

        public void SetBaseStringBuilder(OAuthBaseStringBuilder Builder)
        {
            this._baseStringBuilder = Builder;
        }

        public void SetSignatureProvider(OAuthSignatureProvider Provider)
        {
            this._signatureProvider = Provider;
        }

        public void SetAuthorizationHeaderBuilder(OAuthAuthorizationHeaderBuilder Builder)
        {
            this._authorizationHeaderBuilder = Builder;
        }

        public void RequestToken()
        {
            this.EnsureBaseStringBuilderAndSignatureProviderReady();

            // build key.
            var key = string.Format("{0}&{1}", Utils.UrlEncode(this.ClientSecret), string.Empty);

            var baseStr = this._baseStringBuilder.BuildRequestTokenBaseString(this.ClientId, this.GetTimestamp());
            var signature = this._signatureProvider.GetSignature(
                Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(baseStr));

            if (this.BeforeRequestToken != null)
                this.BeforeRequestToken(this, new OAuthTokenEventArgs()
                    {
                        BaseString = baseStr,
                        Signature = Convert.ToBase64String(signature)
                    });

            var request = this.GetRequestForRequestToken();
            request.Method = "POST";
            request.Headers.Add("Authorization", "OAuth " + 
                this._authorizationHeaderBuilder.GetAuthorizationHeader(Convert.ToBase64String(signature)));

            request.GetRequestStream().Close();

            try
            {
                var response = request.GetResponse() as HttpWebResponse;
                var sreader = new StreamReader(response.GetResponseStream());

                var tokens = Utils.ParseQueryString(sreader.ReadToEnd());
                sreader.Close();

                if (this.ReadyRedirect == null)
                    throw new OAuthFailedException("MISSING_REDIRECT_EVENT_LISTENER");
                
                this.Token = tokens["oauth_token"];
                this.TokenSecret = tokens["oauth_token_secret"];

                this.ReadyRedirect(this, new OAuthTokenReadyToRedirectEventArgs()
                    {
                        Token = this.Token
                    });
            }
            catch (WebException we)
            {
                var errorResponse = we.Response as HttpWebResponse;
                string errorInfo = (new StreamReader(errorResponse.GetResponseStream())).ReadToEnd();

                if (errorResponse.StatusCode == HttpStatusCode.Unauthorized)
                    throw new OAuthFailedException("ERROR_UNAUTHORIZED", errorInfo, 
                        Convert.ToBase64String(signature), baseStr,
                        this._authorizationHeaderBuilder.GetAuthorizationHeader(Convert.ToBase64String(signature)));
                else if (errorResponse.StatusCode == HttpStatusCode.BadRequest)
                    throw new OAuthFailedException("ERROR_BAD_REQUEST", errorInfo,
                        Convert.ToBase64String(signature), baseStr,
                        this._authorizationHeaderBuilder.GetAuthorizationHeader(Convert.ToBase64String(signature)));
                else
                    throw new OAuthFailedException("ERROR_OTHER", errorInfo,
                        Convert.ToBase64String(signature), baseStr,
                        this._authorizationHeaderBuilder.GetAuthorizationHeader(Convert.ToBase64String(signature)));
            }
        }

        public void AccessToken(string Token, string Verifier)
        {
            this.EnsureBaseStringBuilderAndSignatureProviderReady();

            // build key.
            var key = string.Format("{0}&{1}", Utils.UrlEncode(this.ClientSecret), this.TokenSecret);

            var baseStr = this._baseStringBuilder.BuildAccessTokenBaseString(this.ClientId, Token, Verifier, this.GetTimestamp());
            var signature = this._signatureProvider.GetSignature(
                Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(baseStr));

            if (this.BeforeAccessToken != null)
                this.BeforeAccessToken(this, new OAuthTokenEventArgs()
                {
                    BaseString = baseStr,
                    Signature = Convert.ToBase64String(signature)
                });

            var request = this.GetRequestForAccessToken();
            request.Headers.Add("Authorization", "OAuth " +
                this._authorizationHeaderBuilder.GetAuthorizationHeader(Convert.ToBase64String(signature)));

            var swriter = new StreamWriter(request.GetRequestStream());
            swriter.Write("oauth_verifier=" + Verifier);
            swriter.Close();

            try
            {
                var response = request.GetResponse() as HttpWebResponse;
                var sreader = new StreamReader(response.GetResponseStream());
                var queryString = sreader.ReadToEnd();

                var tokens = Utils.ParseQueryString(queryString);
                sreader.Close();

                this.Token = tokens["oauth_token"];
                this.TokenSecret = tokens["oauth_token_secret"];

                if (this.Completed != null)
                    this.Completed(this, new OAuthCompletedEventArgs()
                        {
                            Data = queryString
                        });
            }
            catch (WebException we)
            {
                var errorResponse = we.Response as HttpWebResponse;
                string errorInfo = (new StreamReader(errorResponse.GetResponseStream())).ReadToEnd();

                if (errorResponse.StatusCode == HttpStatusCode.Unauthorized)
                    throw new OAuthFailedException("ERROR_UNAUTHORIZED", errorInfo,
                        Convert.ToBase64String(signature), baseStr,
                        this._authorizationHeaderBuilder.GetAuthorizationHeader(Convert.ToBase64String(signature)));
                else if (errorResponse.StatusCode == HttpStatusCode.BadRequest)
                    throw new OAuthFailedException("ERROR_BAD_REQUEST", errorInfo,
                        Convert.ToBase64String(signature), baseStr,
                        this._authorizationHeaderBuilder.GetAuthorizationHeader(Convert.ToBase64String(signature)));
                else
                    throw new OAuthFailedException("ERROR_OTHER", errorInfo,
                        Convert.ToBase64String(signature), baseStr,
                        this._authorizationHeaderBuilder.GetAuthorizationHeader(Convert.ToBase64String(signature)));
            }
        }

        public void AccessToken(string LoginCallbackData)
        {
            throw new NotSupportedException(); // do not implement in OAuth 1.0a
        }

        public byte[] ConsumeService(Uri ServiceUri, string HttpMethod, byte[] Parameters)
        {
            this.EnsureBaseStringBuilderAndSignatureProviderReady();
            return null;
        }

        public virtual void InvalidateToken()
        {
            // override if provider needs.
        }

        public virtual void RenewToken()
        {
            // override if provider needs.
        }

        protected abstract HttpWebRequest GetRequestForRequestToken();
        protected abstract HttpWebRequest GetRequestForAccessToken();

        private long GetTimestamp()
        {
            var startDateTime = new DateTime(1970, 1, 1, 0, 0, 0);
            var ts = DateTime.UtcNow - startDateTime.ToUniversalTime();
            return Convert.ToInt64(ts.TotalSeconds);
        }

        private void EnsureBaseStringBuilderAndSignatureProviderReady()
        {
            if (this._baseStringBuilder == null)
                throw new OAuthBaseStringBuilderNotFoundException();
            if (this._signatureProvider == null)
                throw new OAuthSignatureProviderNotFoundException();
            if (this._authorizationHeaderBuilder == null)
                throw new OAuthAuthorizationHeaderBuilderNotFoundException();
        }
    }
}
