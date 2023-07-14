using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyScimApp.Models
{
    public class IdentityServer4Model
    {
      
    }
    public class RegisterClientModel
    {
        public string ClientId { get; set; }
        public string ClientName { get; set; }
        public string ClientSecret { get; set; }
        public string RedirectUris { get; set; }
        public string GrantType { get; set; }
        public string[] Scope { get; set; }
        public string PostLogoutRedirectUris { get; set; }
        public string FrontChannelLogoutUri { get; set; }
        public string BackChannelLogoutUri { get; set; }
        public int AccessTokenLifetimeSeconds { get; set; } = 3600;
    }
}
