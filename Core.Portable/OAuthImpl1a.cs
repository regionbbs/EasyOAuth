using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace EasyOAuth.Core.Portable
{
    public abstract class OAuthImpl1a : OAuth
    {
        public event EventHandler<OAuthTokenEventArgs> BeforeRequestToken;
        public event EventHandler<OAuthTokenEventArgs> BeforeAccessToken;
        public event EventHandler<OAuthTokenEventArgs> BeforeConsumeService;
        public event EventHandler<OAuthTokenReadyToRedirectEventArgs> ReadyRedirect;

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

            ManualResetEvent mevent = new ManualResetEvent(false);
            var request = this.GetRequestForRequestToken();
            request.ContentType = "application/x-www-form-urlencoded";
            request.Headers[HttpRequestHeader.Authorization] =
                "Authorization: OAuth " +
                this._authorizationHeaderBuilder.GetAuthorizationHeader(Convert.ToBase64String(signature));

            request.BeginGetRequestStream((ar) =>
                {
                    var s = request.EndGetRequestStream(ar);
                    s.Flush();
                    mevent.Set();
                }, null);

            mevent.WaitOne();
            mevent.Reset();

            try
            {
                request.BeginGetResponse((ar) =>
                {
                    var response = request.EndGetResponse(ar) as HttpWebResponse;
                    var s = response.GetResponseStream();
                    mevent.Set();
                }, null);

                mevent.WaitOne();

                NameValueCollection tokens = null;
                Task<Stream> getResponseTask = Task<Stream>.Factory.FromAsync(
                    request.BeginGetResponse,
                    (ar) =>
                    {
                        try
                        {
                            var response = request.EndGetResponse(ar) as HttpWebResponse;
                            return response.GetResponseStream();
                        }
                        catch (Exception ex)
                        {
                            throw;
                        }
                    },
                    request);

                using (var responseStream = getResponseTask.Result)
                {
                    var sreader = new StreamReader(responseStream);
                    tokens = Utils.ParseQueryString(sreader.ReadToEnd());
                }

                this.Token = tokens["oauth_token"];
                this.TokenSecret = tokens["oauth_token_secret"];

                if (this.ReadyRedirect == null)
                    throw new OAuthFailedException("MISSING_REDIRECT_EVENT_LISTENER");

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
            request.Headers[HttpRequestHeader.Authorization] =
                "Authorization: OAuth " +
                this._authorizationHeaderBuilder.GetAuthorizationHeader(Convert.ToBase64String(signature));

            Task<Stream> getRequestStreamTask = Task.Factory.FromAsync(
                request.BeginGetRequestStream,
                ar => (ar.AsyncState as HttpWebRequest).EndGetRequestStream(ar),
                TaskCreationOptions.None);

            getRequestStreamTask.ContinueWith(t =>
                {
                    using (var stream = t.Result)
                    {
                        var swriter = new StreamWriter(stream);
                        swriter.Write("oauth_verifier=" + Verifier);
                    }
                }).Wait();

            try
            {
                Task<WebResponse> getResponseTask = Task.Factory.FromAsync(
                    request.BeginGetResponse,
                    ar => request.EndGetResponse(ar),
                    TaskCreationOptions.None);

                NameValueCollection tokens = null;

                getResponseTask.ContinueWith(t =>
                {
                    HttpWebResponse response = t.Result as HttpWebResponse;
                    using (var responseStream = response.GetResponseStream())
                    {
                        var sreader = new StreamReader(response.GetResponseStream());
                        tokens = Utils.ParseQueryString(sreader.ReadToEnd());
                    }
                });

                this.Token = tokens["oauth_token"];
                this.TokenSecret = tokens["oauth_token_secret"];
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
