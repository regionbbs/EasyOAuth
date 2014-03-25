using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace EasyOAuth.Core
{
    public static class Utils
    {
        private const string ReservedChars = @"`!@#$%^&*()_-+=.~,:;'?/|\[] ";
        private const string UnReservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

        public static string UrlEncode(string value)
        {
            var result = new StringBuilder();

            if (string.IsNullOrEmpty(value))
                return string.Empty;

            foreach (var symbol in value)
            {
                if (UnReservedChars.IndexOf(symbol) != -1)
                    result.Append(symbol);
                else if (ReservedChars.IndexOf(symbol) != -1)
                    result.Append('%' + String.Format("{0:X2}", (int)symbol).ToUpper());
                else
                {
                    var encoded = HttpUtility.UrlEncode(symbol.ToString()).ToUpper();

                    if (!string.IsNullOrEmpty(encoded))
                        result.Append(encoded);
                }
            }

            return result.ToString();
        }

        public static NameValueCollection ParseQueryString(string Query)
        {
            string query = null;
            var collection = new NameValueCollection();

            if (string.IsNullOrEmpty(Query))
                return new NameValueCollection();

            if (Query.Length > 0 && Query[0] == '?')
                query = Query.Substring(1);
            else
                query = Query;

            string[] items = query.Split('&');

            foreach (var item in items)
            {
                var pair = item.Split('=');

                if (pair.Length > 1)
                    collection.Add(pair[0], pair[1]);
                else
                    collection.Add(pair[0], string.Empty);
            }

            return collection;
        }
    }
}
