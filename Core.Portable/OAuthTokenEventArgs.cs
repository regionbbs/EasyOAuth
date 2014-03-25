using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EasyOAuth.Core.Portable
{
    public class OAuthTokenEventArgs : EventArgs
    {
        public string BaseString { get; set; }
        public string Signature { get; set; }
    }
}
