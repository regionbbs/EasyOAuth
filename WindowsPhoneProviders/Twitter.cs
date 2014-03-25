using EasyOAuth.Core.Portable;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EasyOAuth.Providers.WinPhone
{
    public class Twitter : OAuthImpl1a,
        OAuthBaseStringBuilder, OAuthSignatureProvider, OAuthAuthorizationHeaderBuilder
    {
        public const string RequestTokenUrl = "https://api.twitter.com/oauth/request_token";
        public const string AccessTokenUrl = "https://api.twitter.com/oauth/access_token";

        Func<IDictionary<string, string>, string> baseStrFunc = new Func<IDictionary<string, string>, string>(d =>
        {
            var baseStrBuilder = new StringBuilder();

            foreach (var di in d)
            {
                if (di.Key != "oauth_signature")
                {
                    if (baseStrBuilder.Length != 0)
                        baseStrBuilder.Append(Utils.UrlEncode("&"));

                    baseStrBuilder.Append(Utils.UrlEncode(di.Key + "=" + di.Value));
                }
            }

            return baseStrBuilder.ToString();
        });

        private Dictionary<string, string> _oauthRequestParams = null;
        private string _callbackUrl = null;

        public Twitter(string CallbackUrl, string ConsumerKey, string ConsumerSecret) :
            base(ConsumerKey, ConsumerSecret)
        {
            this._callbackUrl = CallbackUrl;
            this._oauthRequestParams = new Dictionary<string, string>();

            this.SetBaseStringBuilder(this);
            this.SetSignatureProvider(this);
            this.SetAuthorizationHeaderBuilder(this);
        }

        public Twitter(string CallbackUrl, string ConsumerKey, string ConsumerSecret, string Token, string TokenSecret) :
            base(ConsumerKey, ConsumerSecret, Token, TokenSecret)
        {
            this._callbackUrl = CallbackUrl;
            this._oauthRequestParams = new Dictionary<string, string>();

            this.SetBaseStringBuilder(this);
            this.SetSignatureProvider(this);
            this.SetAuthorizationHeaderBuilder(this);
        }

        protected override HttpWebRequest GetRequestForRequestToken()
        {
            var request = WebRequest.Create(RequestTokenUrl) as HttpWebRequest;
            request.Method = "POST";
            return request;
        }

        protected override HttpWebRequest GetRequestForAccessToken()
        {
            var request = WebRequest.Create(AccessTokenUrl) as HttpWebRequest;
            request.Method = "POST";
            return request;
        }

        public string BuildRequestTokenBaseString(string ConsumerKey, long Timestamp)
        {
            this._oauthRequestParams = new Dictionary<string, string>()
            {
                {"oauth_callback", Utils.UrlEncode(this._callbackUrl)},
                {"oauth_consumer_key", ConsumerKey},
                {"oauth_nonce", (new Random()).Next(1000000, 9999999).ToString()},
                {"oauth_signature", ""},
                {"oauth_signature_method", "HMAC-SHA1"},
                {"oauth_timestamp", Timestamp.ToString()},
                {"oauth_version", "1.0"}
            };

            var baseStr = string.Format("{0}&{1}&{2}",
                "POST",
                Utils.UrlEncode(RequestTokenUrl),
                this.baseStrFunc(this._oauthRequestParams));

            return baseStr;
        }

        public string BuildAccessTokenBaseString(string ConsumerKey, string Token, string Verifier, long Timestamp)
        {
            this._oauthRequestParams = new Dictionary<string, string>()
            {
                {"oauth_consumer_key", ConsumerKey},
                {"oauth_nonce", (new Random()).Next(1000000, 9999999).ToString()},
                {"oauth_signature", ""},
                {"oauth_signature_method", "HMAC-SHA1"},
                {"oauth_timestamp", Timestamp.ToString()},
                {"oauth_token", Token},
                {"oauth_version", "1.0"}
            };

            var baseStr = string.Format("{0}&{1}&{2}",
                "POST",
                Utils.UrlEncode(AccessTokenUrl),
                this.baseStrFunc(this._oauthRequestParams));

            return baseStr;
        }

        public string BuildServiceConsumptionBaseString(string ServiceUrl, string ConsumerKey, string Token, long Timestamp)
        {
            throw new NotImplementedException();
        }

        public OAuthSignatureMethods GetSignatureMethod()
        {
            return OAuthSignatureMethods.HMACSHA1;
        }

        public byte[] GetSignature(byte[] Key, byte[] DataToSignature)
        {
            HMACSHA1 signer = new HMACSHA1(Key);
            return signer.ComputeHash(DataToSignature);
        }

        public string GetAuthorizationHeader(string Signature)
        {
            var headerStrBuilder = new StringBuilder();
            this._oauthRequestParams["oauth_signature"] = Utils.UrlEncode(Signature);

            foreach (var param in this._oauthRequestParams)
            {
                if (headerStrBuilder.Length != 0)
                    headerStrBuilder.Append(",");

                headerStrBuilder.Append(param.Key + "=" + param.Value);
            }

            return headerStrBuilder.ToString();
        }
    }
}
