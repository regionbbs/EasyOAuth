using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EasyOAuth.Core
{
    public interface OAuth
    {
        void RequestToken();
        void AccessToken(string Token, string Verifier);
        void AccessToken(string CallbackData);
        byte[] ConsumeService(Uri ServiceUri, string HttpMethod, byte[] Parameters);
        void InvalidateToken();
        void RenewToken();
    }
}
