using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace MyScimApp.Models
{
    public class ScimUser
    {
        public int ScimUserId { get; set; }

        [NotMapped]
        public IList<string> Schemas { get; set; }
        public string ExternalId { get; set; }
        public string UserName { get; set; }
        public bool Active { get; set; }
        public string UserType { get; set; }

        [NotMapped]
        public IList<string> Roles { get; set; }
        public string DisplayName { get; set; }
        public virtual ScimUserName Name { get; set; }
        public virtual ICollection<ScimUserPhoneNumber> PhoneNumbers { get; set; }
        public virtual ICollection<ScimUserEmail> Emails { get; set; }
        public virtual ScimUserMetaData Meta { get; set; }
        public string ApplicationUserId { get; set; }
        public virtual ApplicationUser ApplicationUser { get; set; }
    }
    public class ScimUserName
    {
        public int ScimUserNameId { get; set; }
        public string Formatted { get; set; }
        public string FamilyName { get; set; }
        public string GivenName { get; set; }
        public int ScimUserId { get; set; }
        public virtual ScimUser ScimUser { get; set; }

    }

    public class ScimUserPhoneNumber
    {
        public int ScimUserPhoneNumberId { get; set; }
        public string Value { get; set; }
        public string Type { get; set; }
        public int ScimUserId { get; set; }
        public virtual ScimUser ScimUser { get; set; }
    }

    public class ScimUserEmail
    {
        public int ScimUserEmailId { get; set; }
        public bool Primary { get; set; }
        public string Type { get; set; }
        public string Value { get; set; }
        public int ScimUserId { get; set; }
        public virtual ScimUser ScimUser { get; set; }
    }

    public class ScimUserMetaData
    {
        public int ScimUserMetaDataId { get; set; }
        public string ResourceType { get; set; }
        public DateTime Created { get; set; }
        public DateTime LastModified { get; set; }
        public string Location { get; set; }
        public string Version { get; set; }
        public int ScimUserId { get; set; }
        public virtual ScimUser ScimUser { get; set; }

    }
}
