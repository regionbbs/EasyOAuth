using EasyOAuth.Providers.Web;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace WebMvcExample.Controllers
{
    public class GoogleOAuthController : Controller
    {
        public ActionResult Index()
        {
            Google google = new Google(
                "http://twitteroauth.azurewebsites.net/GoogleOAuth/callback",
                "781275012988-lbgfkqtb3bitpp8a7m50hfqoio36ln4o.apps.googleusercontent.com",
                "Z28NOKw8opUasvqaR4zYHrVs",
                "profile email");

            string redirectUrl = null;

            google.ReadyRedirect += (s, e) =>
            {
                redirectUrl = e.RedirectUrl;
            };

            google.RequestToken();

            TempData["oauth"] = google;

            return Redirect(redirectUrl);
        }

        public ActionResult Callback(string state, string code)
        {
            Google google = TempData["oauth"] as Google;
            google.AccessToken(code);

            byte[] data = google.ConsumeService(
                new Uri("https://www.googleapis.com/plus/v1/people/me"), "GET", null);

            return Content(Encoding.UTF8.GetString(data), "text/plain");
        }
	}
}