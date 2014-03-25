using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EasyOAuth.Core;
using EasyOAuth.Providers;
using System.Net;
using System.IO;

namespace EasyOAuth.Providers.Web
{
    public class Facebook : OAuthImpl2
    {
        private string _redirectUri = null;
        private const string RequestTokenUrl = "https://www.facebook.com/dialog/oauth?client_id={0}&redirect_uri={1}&scope={2}";
        private const string AccessTokenUrl = "https://graph.facebook.com/oauth/access_token?client_id={0}&redirect_uri={1}&client_secret={2}&code={3}";

        public Facebook(string RedirectUrl, string ConsumerKey, string ConsumerSecret, string Scope)
            : base(ConsumerKey, ConsumerSecret, Scope)
        {
            this._redirectUri = RedirectUrl;
        }

        public override void RequestToken()
        {
            this.OnReadyRedirect(new OAuthTokenReadyToRedirectEventArgs()
                {
                    RedirectUrl = string.Format(
                    RequestTokenUrl,
                    this.ClientKey,
                    Utils.UrlEncode(this._redirectUri),
                    Utils.UrlEncode(this.Scope))
                });
        }

        public override void AccessToken(string LoginCallbackData)
        {
            var data = Utils.ParseQueryString(LoginCallbackData);

            // compatibility for ASP.NET HTTP Handler.
            if (data.AllKeys.Contains("error"))
            {
                throw new OAuthFailedException("ERROR_USER_DENIED",
                    string.Format("error: {0}, reason: {1}, description: {2}",
                    data["error"],
                    data["error_description"],
                    data["error_reason"]));
            }

            string code = null;

            if (data != null && data.AllKeys.Contains("code"))
                code = data["code"];
            else
                code = LoginCallbackData;

            WebClient client = new WebClient();
            string accessToken = client.DownloadString(string.Format(
                AccessTokenUrl,
                this.ClientKey,
                this._redirectUri,
                this.ClientSecret,
                code));

            this.Token = Utils.ParseQueryString(accessToken)["access_token"];
            this.TokenExpires = DateTime.Now.AddSeconds(
                Convert.ToInt32(Utils.ParseQueryString(accessToken)["expires"]));
        }

        public override byte[] ConsumeService(Uri ServiceUri, string HttpMethod, byte[] Parameters)
        {
            // apply access token.
            if (string.IsNullOrEmpty(ServiceUri.Query))
                ServiceUri = new Uri(ServiceUri.ToString() + "?access_token=" + this.Token);
            else
                ServiceUri = new Uri(ServiceUri.ToString() + "&access_token=" + this.Token);

            var request = WebRequest.Create(ServiceUri) as HttpWebRequest;
            request.Method = HttpMethod;

            if (HttpMethod == "POST" || HttpMethod == "PUT")
            {
                var requestStream = request.GetRequestStream();

                if (Parameters != null && Parameters.Length > 0)
                    requestStream.Write(Parameters, 0, Parameters.Length);

                requestStream.Close();
            }

            try
            {
                var response = request.GetResponse();
                var responseStream = response.GetResponseStream();
                var ms = new MemoryStream();
                byte[] data = new byte[4096];
                int readcount = 0;

                do
                {
                    readcount = responseStream.Read(data, 0, data.Length);

                    if (readcount == 0)
                        break;

                    ms.Write(data, 0, readcount);
                }
                while (readcount > 0);

                responseStream.Close();

                ms.Flush();
                ms.Position = 0;

                data = ms.ToArray();
                ms.Close();

                return data;
            }
            catch (WebException we)
            {
                var errorResponse = we.Response as HttpWebResponse;
                string errorInfo = (new StreamReader(errorResponse.GetResponseStream())).ReadToEnd();

                if (errorResponse.StatusCode == HttpStatusCode.Unauthorized)
                    throw new OAuthFailedException("ERROR_UNAUTHORIZED", errorInfo);
                else if (errorResponse.StatusCode == HttpStatusCode.BadRequest)
                    throw new OAuthFailedException("ERROR_BAD_REQUEST", errorInfo);
                else
                    throw new OAuthFailedException("ERROR_OTHER", errorInfo);
            }
        }

        public override void InvalidateToken()
        {
            var client = new WebClient();
            client.DownloadString(string.Format(
                "http://www.facebook.com/logout.php?access_token={0}&confirm=1", this.Token));
        }
    }
}
