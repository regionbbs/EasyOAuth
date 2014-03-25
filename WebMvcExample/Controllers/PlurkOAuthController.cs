using EasyOAuth.Core;
using EasyOAuth.Providers.Web;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace WebMvcExample.Controllers
{
    public class PlurkOAuthController : Controller
    {
        public ActionResult Index()
        {
            Plurk plurk = new Plurk(
                "http://twitteroauth.azurewebsites.net/PlurkOAuth/callback",
                "vmtp91dqGuZG",
                "wZMVVebQkLMFuuastaX0PiwORzfoByIF");

            string token = null;

            plurk.ReadyRedirect += (s, e) =>
            {
                token = e.Token;
            };

            try
            {
                plurk.RequestToken();

                TempData["oauth"] = plurk;

                return Redirect(
                    "http://www.plurk.com/OAuth/authorize?oauth_token=" + token);
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
            Plurk plurk = TempData["oauth"] as Plurk;

            try
            {
                plurk.AccessToken(oauth_token, oauth_verifier);
                return Content(plurk.Token, "text/plain");
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