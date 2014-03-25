using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EasyOAuth.Core
{
    public interface OAuthAuthorizationHeaderBuilder
    {
        string GetAuthorizationHeader(string Signature);
    }
}
