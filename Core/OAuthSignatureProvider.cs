using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace EasyOAuth.Core
{
    public interface OAuthSignatureProvider
    {
        OAuthSignatureMethods GetSignatureMethod();
        byte[] GetSignature(byte[] Key, byte[] DataToSignature);
    }
}
