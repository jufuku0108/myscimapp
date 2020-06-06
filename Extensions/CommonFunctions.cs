using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace MyScimApp.Extensions
{
    public static class CommonFunctions
    {
        public static JObject CreateErrorJobject(Exception exception)
        {
            JObject jObject = new JObject
            {
                new JProperty("schemas",new JArray("urn:ietf:params:scim:api:messages:2.0:Error")),
                new JProperty("scimType", "invalidValue"),
                new JProperty("detail",exception.Message),
                new JProperty("status",500)

            };
            return jObject;

        }

        public static JObject CreateFilteredJobject(JObject jObject)
        {
            if(jObject.Count != 0)
            {
                JObject jo = new JObject
                {
                    new JProperty("schemas", new JArray("urn:ietf:params:scim:api:messages:2.0:ListResponse")),
                    new JProperty("totalResults", 1),
                    new JProperty("Resources", new JArray(jObject)),
                    new JProperty("startIndex", 1),
                    new JProperty("itemsPerPage", 20)
                };
                return jo;
            }
            else
            {
                JObject jo = new JObject
                {
                    new JProperty("schemas", new JArray("urn:ietf:params:scim:api:messages:2.0:ListResponse")),
                    new JProperty("totalResults", 0),
                    new JProperty("Resources", new JArray()),
                    new JProperty("startIndex", 1),
                    new JProperty("itemsPerPage", 20)
                };
                return jo;
            }
 
        }


        public static readonly SHA256CryptoServiceProvider sha256CryptoServiceProvider = new SHA256CryptoServiceProvider();
        public static string GetSHA256HashedString(string value)
        {

            return String.Join("", sha256CryptoServiceProvider.ComputeHash(System.Text.Encoding.UTF8.GetBytes(value)).Select(x => $"{x:X2}"));
        }
        public static string FormatException(Exception exception)
        {
            return string.Format("{0}{1}", exception.Message, exception.InnerException != null ? "(" + exception.InnerException + ")" : "");
        }

    }

}
