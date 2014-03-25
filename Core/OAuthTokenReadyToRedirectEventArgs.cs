using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EasyOAuth.Core
{
    public class OAuthTokenReadyToRedirectEventArgs : EventArgs
    {
        public string Token { get; set; }
        public string RedirectUrl { get; set; }
    }
}
