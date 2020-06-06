using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyScimApp.Models
{
    public class AccessLog
    {
        public int AccessLogId { get; set; }
        public DateTime DateTime { get; set; }
        public string Type { get; set; }
        public string HttpMethod { get; set; }
        public string StatusCode { get; set; }
        public string AbsoluteUrl { get; set; }
        public string Headers { get; set; }
        public string Body { get; set; }

    }
}
