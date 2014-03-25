using EasyOAuth.Core.Portable;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Ink;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;

namespace EasyOAuth.Providers.WinPhone
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

        public async override void AccessToken(string LoginCallbackData)
        {
            var data = Utils.ParseQueryString(LoginCallbackData);

            // compatibility for ASP.NET HTTP Handler.
            if (data.Keys.Contains("error"))
            {
                throw new OAuthFailedException("ERROR_USER_DENIED",
                    string.Format("error: {0}, reason: {1}, description: {2}",
                    data["error"],
                    data["error_description"],
                    data["error_reason"]));
            }

            string code = null;

            if (data != null && data.Keys.Contains("code"))
                code = data["code"];
            else
                code = LoginCallbackData;

            HttpClient client = new HttpClient();
            string accessToken = await client.GetStringAsync(string.Format(
                AccessTokenUrl,
                this.ClientKey,
                this._redirectUri,
                this.ClientSecret,
                code));
            
            this.Token = Utils.ParseQueryString(accessToken)["access_token"];
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
                if (Parameters != null && Parameters.Length > 0)
                {
                    Task<Stream> getRequestStream = Task.Factory.FromAsync(
                        request.BeginGetRequestStream,
                        ar => request.EndGetRequestStream(ar),
                        TaskCreationOptions.None);

                    getRequestStream.ContinueWith(t =>
                        {
                            t.Result.Write(Parameters, 0, Parameters.Length);
                        }).Wait();
                }
            }

            try
            {
                Task<WebResponse> getResponseTask = Task.Factory.FromAsync(
                    request.BeginGetResponse,
                    ar => request.EndGetResponse(ar),
                    TaskCreationOptions.None);
                var ms = new MemoryStream();

                getResponseTask.ContinueWith(t =>
                    {
                        using (var s = t.Result.GetResponseStream())
                        {
                            byte[] d = new byte[4096];
                            int readcount = 0;

                            do
                            {
                                readcount = s.Read(d, 0, d.Length);

                                if (readcount == 0)
                                    break;

                                ms.Write(d, 0, readcount);
                            }
                            while (readcount > 0);
                        }
                    }).Wait();

                ms.Flush();
                ms.Position = 0;

                byte[] data = ms.ToArray();
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
    }
}
