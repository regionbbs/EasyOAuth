using EasyOAuth.Providers.Web;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace WebMvcExample.Controllers
{
    public class DropBoxOAuthController : Controller
    {
        public ActionResult Index()
        {
            DropBox dropbox = new DropBox(
                "http://localhost:10493/DropBoxOAuth/callback",
                "ulinnbzqxokqxbc",
                "xvjv5j2lokymztr",
                "email");

            string redirectUrl = null;

            dropbox.ReadyRedirect += (s, e) =>
            {
                redirectUrl = e.RedirectUrl;
            };

            dropbox.RequestToken();

            TempData["oauth"] = dropbox;

            return Redirect(redirectUrl);
        }

        public ActionResult Callback(string state, string code)
        {
            DropBox dropbox = TempData["oauth"] as DropBox;
            dropbox.AccessToken(code);

            byte[] accountInfo = 
                dropbox.ConsumeService(new Uri("https://api.dropbox.com/1/account/info"), "POST", null);

            return Content(Encoding.UTF8.GetString(accountInfo), "text/plain");
        }
	}
}