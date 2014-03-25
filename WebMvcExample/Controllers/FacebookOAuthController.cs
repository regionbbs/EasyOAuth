using EasyOAuth.Providers.Web;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace WebMvcExample.Controllers
{
    public class FacebookOAuthController : Controller
    {
        public ActionResult Index()
        {
            Facebook fb = new Facebook(
                "http://twitteroauth.azurewebsites.net/FacebookOAuth/callback",
                "157813327575516",
                "1a16c14fe956785e1876c1df665beaf0",
                "email");

            string redirectUrl = null;

            fb.ReadyRedirect += (s, e) =>
            {
                redirectUrl = e.RedirectUrl;
            };

            fb.RequestToken();

            TempData["oauth"] = fb;

            return Redirect(redirectUrl);
        }

        public ActionResult Callback(string code)
        {
            Facebook fb = TempData["oauth"] as Facebook;
            fb.AccessToken(code);
            byte[] data = fb.ConsumeService(new Uri("https://graph.facebook.com/me"), "GET", null);

            return Content(Encoding.UTF8.GetString(data), "text/plain");
        }
	}
}