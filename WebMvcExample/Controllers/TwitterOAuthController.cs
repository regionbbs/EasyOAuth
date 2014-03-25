using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using EasyOAuth.Core;
using EasyOAuth.Providers.Web;

namespace WebMvcExample.Controllers
{
    public class TwitterOAuthController : Controller
    {
        public ActionResult Index()
        {
            Twitter twitter = new Twitter(
                "http://twitteroauth.azurewebsites.net/TwitterOAuth/callback",
                "WiSyL3EUURWpxXdQSWLIgA",
                "v1A76pOeKR9Xim1yWDskymTIRi2exF6kEKDLTX04");

            string token = null;

            twitter.ReadyRedirect += (s, e) =>
                {
                    token = e.Token;
                };

            try
            {
                twitter.RequestToken();

                TempData["oauth"] = twitter;

                return Redirect(
                    "https://api.twitter.com/oauth/authenticate?oauth_token=" + token);
            }
            catch (OAuthFailedException fe)
            {
                return Content(
                    fe.Reason + "\r\n" + "=====" + "\r\n" +
                    fe.Header + "\r\n" + "=====" + "\r\n" +
                    fe.Signature + "\r\n" + "=====" + "\r\n" +
                    fe.BaseString + "\r\n" + "=====" + "\r\n" +
                    fe.ErrorInfo, "text/plain");
            }
        }

        public ActionResult Callback(string oauth_token, string oauth_verifier)
        {
            Twitter twitter = TempData["oauth"] as Twitter;

            try
            {
                twitter.AccessToken(oauth_token, oauth_verifier);
                return Content("OK", "text/plain");
            }
            catch (OAuthFailedException fe)
            {
                return Content(
                    fe.Reason + "\r\n" + "=====" + "\r\n" +
                    fe.Header + "\r\n" + "=====" + "\r\n" +
                    fe.Signature + "\r\n" + "=====" + "\r\n" +
                    fe.BaseString + "\r\n" + "=====" + "\r\n" +
                    fe.ErrorInfo, "text/plain");
            }
        }
    }
}