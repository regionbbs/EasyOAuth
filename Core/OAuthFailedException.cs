using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EasyOAuth.Core
{
    public class OAuthFailedException : Exception
    {
        public string Reason { get; private set; }
        public string ErrorInfo { get; private set; }
        public string Signature { get; private set; }
        public string BaseString { get; private set; }
        public string Header { get; private set; }
        public OAuthFailedException(
            string Reason, 
            string ErrorInfo = null,
            string Signature = null,
            string BaseString = null,
            string Header = null) : base(Reason + ":" + ErrorInfo)
        {
            this.Reason = Reason;
            this.ErrorInfo = ErrorInfo;
            this.Signature = Signature;
            this.BaseString = BaseString;
            this.Header = Header;
        }
    }
}
