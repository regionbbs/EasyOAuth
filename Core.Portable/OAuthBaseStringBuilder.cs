using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EasyOAuth.Core.Portable
{
    public interface OAuthBaseStringBuilder
    {
        string BuildRequestTokenBaseString(string ConsumerKey, long Timestamp);
        string BuildAccessTokenBaseString(string ConsumerKey, string Token, string Verifier, long Timestamp);
        string BuildServiceConsumptionBaseString(string ServiceUrl, string ConsumerKey, string Token, long Timestamp);
    }
}
