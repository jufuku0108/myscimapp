using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyScimApp.Models
{
    public class Saml2ConfigurationViewModel
    {
        public string Issuer { get; set; }
        public string BindingMode { get; set; }
        public string IdPMetadataUrl { get; set; }
        public string EntityId { get; set; }
        public string ReturnUrl { get; set; }
        public string NameIdFormat { get; set; }
    }
    public class Saml2Partner
    {
        public int Saml2PartnerId { get; set; }
        public string Issuer { get; set; }
        public string MetadataUrl { get; set; }
        public string Type { get; set; }
        public string RegisteredBy { get; set; }
    }


}
