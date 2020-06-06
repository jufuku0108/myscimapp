using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace MyScimApp.Models
{
    public class ScimGroup
    {
        public string ScimGroupId { get; set; }
        public string ExternalId { get; set; }
        [NotMapped]
        public string[] Schemas { get; set; }
        public string DisplayName { get; set; }
        public virtual ICollection<ScimGroupMember> Members { get; set; }
        public virtual ScimGroupMetaData Meta { get; set; }
    }

    public class ScimGroupMember
    {
        public int ScimGroupMemberId { get; set; }
        public string Value { get; set; }
        public string Reference { get; set; }

        public string Display { get; set; }
        public string ScimGroupId { get; set; }

        public virtual ScimGroup ScimGroup { get; set; }

    }

    public class ScimGroupMetaData
    {
        public int ScimGroupMetaDataId { get; set; }
        public string ResourceType { get; set; }
        public DateTime Created { get; set; }
        public DateTime LastModified { get; set; }
        public string Location { get; set; }
        public string Version { get; set; }
        public string ScimGroupId { get; set; }
        public virtual ScimGroup ScimGroup { get; set; }

    }
}
