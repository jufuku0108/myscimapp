using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;

namespace MyScimApp.Controllers
{
    public class ScimConfigController : Controller
    {
        [HttpGet]
        [Route("/v2/ServiceProviderConfig", Name = "GetServiceProviderConfig")]
        public IActionResult GetServiceProviderConfig()
        {
            var serviceProviderConfig = CreateServiceProviderConfigJobject();
            Response.Headers.Add("Content-Type", "application/scim+json");
            return Ok(serviceProviderConfig);
        }

        [HttpGet]
        [Route("/v2/ResourceTypes", Name = "GetResourceTypes")]
        public IActionResult GetResourceTypes()
        {
            var resourceTypes = new JArray() { CreateUserResourceTypeJobject(), CreateGroupResourceTypeJobject() };
            Response.Headers.Add("Content-Type", "application/scim+json");
            return Ok(resourceTypes);
        }

        [HttpGet]
        [Route("/v2/UserResourceType", Name = "GetUserResourceType")]
        public IActionResult GetUserResourceType()
        {
            Response.Headers.Add("Content-Type", "application/scim+json");

            var userResourceType = CreateUserResourceTypeJobject();
            return Ok(userResourceType);
        }

        [HttpGet]
        [Route("/v2/GroupResourceType", Name = "GetGroupResourceType")]
        public IActionResult GetGroupResourceType()
        {
            Response.Headers.Add("Content-Type", "application/scim+json");

            var groupResourceType = CreateGroupResourceTypeJobject();
            return Ok(groupResourceType);
        }

        [HttpGet]
        [Route("/v2/Schemas", Name = "GetSchemas")]
        public IActionResult GetSchemas()
        {
            Response.Headers.Add("Content-Type", "application/scim+json");

            var schemas = new JArray() { CreateServiceProviderConfigSchemasJobject()};
            return Ok(schemas);
        }

        private JObject CreateServiceProviderConfigJobject()
        {
            return new JObject()
            {
                new JProperty("schemas",new JArray("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig")),
                new JProperty("documentationUri", null),
                new JProperty("patch", new JObject(){
                    new JProperty("supported",false) }),
                new JProperty("bulk", new JObject(){
                    new JProperty("maxOperations",1000),
                    new JProperty("maxPayloadSize", 1048576),
                    new JProperty("supported",false) }),
                new JProperty("filter",new JObject(){
                    new JProperty("maxResults",200),
                    new JProperty("supported",true) }),
                new JProperty("changePassword",new JObject(){
                    new JProperty("supported",false) }),
                new JProperty("sort",new JObject(){
                    new JProperty("supported",false) }),
                new JProperty("etag",new JObject(){
                    new JProperty("supported",false) }),
                new JProperty("authenticationSchemes",new JArray()),
                new JProperty("meta",new JObject(){
                    new JProperty("resourceType", "ServiceProviderConfig"),
                    new JProperty("created",DateTime.MinValue),
                    new JProperty("lastModified",DateTime.MinValue),
                    new JProperty("location", Url.Link("GetServiceProviderConfig", null)),
                    new JProperty("version","version") }),
            };
        }

        private JObject CreateUserResourceTypeJobject()
        {
            return  new JObject()
            {
                new JProperty("schemas",new JArray("urn:ietf:params:scim:schemas:core:2.0:ResourceType")),
                new JProperty("name", "User"),
                new JProperty("description", "User resource."),
                new JProperty("endpoint", "/v2/users"),
                new JProperty("schema", "urn:ietf:params:scim:schemas:core:2.0:User"),
                new JProperty("schemaExtensions", new JArray(new JObject(){
                    new JProperty("schema","urn:ietf:params:scim: schemas: extension: enterprise: 2.0:User"),
                    new JProperty("required",false)})),
                new JProperty("meta",new JObject(){
                    new JProperty("resourceType", "ResourceType"),
                    new JProperty("created",DateTime.MinValue),
                    new JProperty("lastModified",DateTime.MinValue),
                    new JProperty("location", Url.Link("GetUserResourceType", null)),
                    new JProperty("version","version") }),
            };
        }

        private JObject CreateGroupResourceTypeJobject()
        {
            return new JObject()
            {
                new JProperty("schemas",new JArray("urn:ietf:params:scim:schemas:core:2.0:ResourceType")),
                new JProperty("name", "Group"),
                new JProperty("description", "Group resource."),
                new JProperty("endpoint", "/v2/groups"),
                new JProperty("schema", "urn:ietf:params:scim:schemas:core:2.0:Group"),
                new JProperty("schemaExtensions", new JArray()),
                new JProperty("meta",new JObject(){
                    new JProperty("resourceType", "ResourceType"),
                    new JProperty("created",DateTime.MinValue),
                    new JProperty("lastModified",DateTime.MinValue),
                    new JProperty("location", Url.Link("GetGroupResourceType", null)),
                    new JProperty("version","version") }),
            };
        }
        private JObject CreateServiceProviderConfigSchemasJobject()
        {
            return new JObject()
            {
                new JProperty("schemas",new JArray("urn:ietf:params:scim:schemas:core:2.0:Schema")),
                new JProperty("id", "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"),
                new JProperty("name", "Service Provider Configuration"),
                new JProperty("description", "Schema for representing the service provider's configuration"),
                new JProperty("attributes",new JArray(){
                    new JObject()
                    {
                        new JProperty("name", "documentationUri"),
                        new JProperty("description","An HTTP-addressable URL pointing to the service provider's human-consumable help documentation."),
                        new JProperty("type","reference"),
                        new JProperty("multiValued",false),
                        new JProperty("mutability","readOnly"),
                        new JProperty("required",false),
                        new JProperty("returned","default"),
                        new JProperty("referenceTypes",new JArray(){ "external" }),
                        new JProperty("uniqueness","none")
                    },
                    new JObject()
                    {
                        new JProperty("name", "patch"),
                        new JProperty("description","A complex type that specifies PATCH configuration options."),
                        new JProperty("type","complex"),
                        new JProperty("multiValued",false),
                        new JProperty("mutability","readOnly"),
                        new JProperty("required",true),
                        new JProperty("returned","default"),
                        new JProperty("uniqueness","none"),
                        new JProperty("subAttributes",
                            new JObject()
                            {
                                new JProperty("name","supported"),
                                new JProperty("description","A boolean value specifying whether or not the operation is supported."),
                                new JProperty("type","boolean"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",true),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            })
                    },
                    new JObject()
                    {
                        new JProperty("name", "bulk"),
                        new JProperty("description","A complex type that specifies bulk configuration options."),
                        new JProperty("type","complex"),
                        new JProperty("multiValued",false),
                        new JProperty("mutability","readOnly"),
                        new JProperty("required",true),
                        new JProperty("returned","default"),
                        new JProperty("uniqueness","none"),
                        new JProperty("subAttributes",new JArray(){
                            new JObject()
                            {
                                new JProperty("name","maxOperations"),
                                new JProperty("description","An integer value specifying the maximum number of operations."),
                                new JProperty("type","integer"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",true),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","maxPayloadSize"),
                                new JProperty("description","An integer value specifying the maximum payload size in bytes."),
                                new JProperty("type","integer"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",true),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","supported"),
                                new JProperty("description","A boolean value specifying whether or not the operation is supported."),
                                new JProperty("type","boolean"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",true),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            }
                        })
                    },
                    new JObject()
                    {
                        new JProperty("name", "filter"),
                        new JProperty("description","A complex type that specifies FILTER options."),
                        new JProperty("type","complex"),
                        new JProperty("multiValued",false),
                        new JProperty("mutability","readOnly"),
                        new JProperty("required",true),
                        new JProperty("returned","default"),
                        new JProperty("uniqueness","none"),
                        new JProperty("subAttributes",new JArray(){
                            new JObject()
                            {
                                new JProperty("name","maxResults"),
                                new JProperty("description","An integer value specifying the maximum number of resources returned in a response."),
                                new JProperty("type","integer"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",true),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","supported"),
                                new JProperty("description","A boolean value specifying whether or not the operation is supported."),
                                new JProperty("type","boolean"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",true),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            }
                        })
                    },
                    new JObject()
                    {
                        new JProperty("name", "changePassword"),
                        new JProperty("description","A complex type that specifies configuration options related to changing a password."),
                        new JProperty("type","complex"),
                        new JProperty("multiValued",false),
                        new JProperty("mutability","readOnly"),
                        new JProperty("required",true),
                        new JProperty("returned","default"),
                        new JProperty("uniqueness","none"),
                        new JProperty("subAttributes",new JArray(){
                            new JObject()
                            {
                                new JProperty("name","supported"),
                                new JProperty("description","A boolean value specifying whether or not the operation is supported."),
                                new JProperty("type","boolean"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",true),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            }
                        })
                    },
                    new JObject()
                    {
                        new JProperty("name", "sort"),
                        new JProperty("description","A complex type that specifies Sort configuration options."),
                        new JProperty("type","complex"),
                        new JProperty("multiValued",false),
                        new JProperty("mutability","readOnly"),
                        new JProperty("required",true),
                        new JProperty("returned","default"),
                        new JProperty("uniqueness","none"),
                        new JProperty("subAttributes",new JArray(){
                            new JObject()
                            {
                                new JProperty("name","supported"),
                                new JProperty("description","A boolean value specifying whether or not the operation is supported."),
                                new JProperty("type","boolean"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",true),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            }
                        })
                    },
                    new JObject()
                    {
                        new JProperty("name", "etag"),
                        new JProperty("description","A complex type that specifies ETag configuration options."),
                        new JProperty("type","complex"),
                        new JProperty("multiValued",false),
                        new JProperty("mutability","readOnly"),
                        new JProperty("required",true),
                        new JProperty("returned","default"),
                        new JProperty("uniqueness","none"),
                        new JProperty("subAttributes",new JArray(){
                            new JObject()
                            {
                                new JProperty("name","isWeak"),
                                new JProperty("description",null),
                                new JProperty("type","boolean"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readWrite"),
                                new JProperty("required",false),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","supported"),
                                new JProperty("description","A boolean value specifying whether or not the operation is supported."),
                                new JProperty("type","boolean"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readWrite"),
                                new JProperty("required",true),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            }
                        })
                    },
                    new JObject()
                    {
                        new JProperty("name", "authenticationSchemes"),
                        new JProperty("description","A multi-valued complex type that specifies supported authentication scheme properties."),
                        new JProperty("type","complex"),
                        new JProperty("multiValued",true),
                        new JProperty("mutability","readOnly"),
                        new JProperty("required",true),
                        new JProperty("returned","default"),
                        new JProperty("uniqueness","none"),
                        new JProperty("subAttributes",new JArray(){
                            new JObject()
                            {
                                new JProperty("name","name"),
                                new JProperty("description","The common authentication scheme name, e.g., HTTP Basic."),
                                new JProperty("type","string"),
                                new JProperty("caseExact",false),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",true),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","description"),
                                new JProperty("description","A description of the authentication scheme."),
                                new JProperty("type","string"),
                                new JProperty("caseExact",false),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",true),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","specUri"),
                                new JProperty("description","An HTTP-addressable URL pointing to the authentication scheme's specification."),
                                new JProperty("type","reference"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",true),
                                new JProperty("returned","default"),
                                new JProperty("referenceTypes",new JArray(){ "external" }),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","documentationUri"),
                                new JProperty("description","An HTTP-addressable URL pointing to the authentication scheme's usage documentation."),
                                new JProperty("type","reference"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",false),
                                new JProperty("returned","default"),
                                new JProperty("referenceTypes",new JArray(){ "external" }),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","type"),
                                new JProperty("description","The authentication scheme."),
                                new JProperty("type","string"),
                                new JProperty("caseExact",false),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",true),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","primary"),
                                new JProperty("description",null),
                                new JProperty("type","boolean"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readWrite"),
                                new JProperty("required",false),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","display"),
                                new JProperty("description",null),
                                new JProperty("type","string"),
                                new JProperty("caseExact",false),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readWrite"),
                                new JProperty("required",false),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","value"),
                                new JProperty("description",null),
                                new JProperty("type","string"),
                                new JProperty("caseExact",false),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readWrite"),
                                new JProperty("required",false),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","$ref"),
                                new JProperty("description",null),
                                new JProperty("type","reference"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",false),
                                new JProperty("returned","default"),
                                new JProperty("referenceTypes",null),
                                new JProperty("uniqueness","none")
                            }
                        })
                    },
                    new JObject()
                    {
                        new JProperty("name", "schemas"),
                        new JProperty("description",null),
                        new JProperty("type","string"),
                        new JProperty("caseExact",false),
                        new JProperty("multiValued",true),
                        new JProperty("mutability","readWrite"),
                        new JProperty("required",false),
                        new JProperty("returned","default"),
                        new JProperty("uniqueness","none")
                    },
                    new JObject()
                    {
                        new JProperty("name", "id"),
                        new JProperty("description","A unique identifier for a SCIM resource as defined by the service provider."),
                        new JProperty("type","string"),
                        new JProperty("caseExact",false),
                        new JProperty("multiValued",false),
                        new JProperty("mutability","readWrite"),
                        new JProperty("required",false),
                        new JProperty("returned","never"),
                        new JProperty("uniqueness","none")
                    },
                    new JObject()
                    {
                        new JProperty("name", "externalId"),
                        new JProperty("description","An identifier for the resource as defined by the provisioning client."),
                        new JProperty("type","string"),
                        new JProperty("caseExact",false),
                        new JProperty("multiValued",false),
                        new JProperty("mutability","readWrite"),
                        new JProperty("required",false),
                        new JProperty("returned","never"),
                        new JProperty("uniqueness","none")
                    },
                    new JObject()
                    {
                        new JProperty("name", "meta"),
                        new JProperty("description",null),
                        new JProperty("type","complex"),
                        new JProperty("multiValued",false),
                        new JProperty("mutability","readWrite"),
                        new JProperty("required",false),
                        new JProperty("returned","default"),
                        new JProperty("uniqueness","none"),
                        new JProperty("subAttributes",new JArray(){
                            new JObject()
                            {
                                new JProperty("name","resourceType"),
                                new JProperty("description","The name of the resource type of the resource."),
                                new JProperty("type","string"),
                                new JProperty("caseExact",true),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",false),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","created"),
                                new JProperty("description","The DateTime that the resource was added to the service provider."),
                                new JProperty("type","datetime"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",false),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","lastModified"),
                                new JProperty("description","The most recent DateTime that the details of this resource were updated at the service provider."),
                                new JProperty("type","datetime"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",false),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","location"),
                                new JProperty("description","The URI of the resource being returned."),
                                new JProperty("type","reference"),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",false),
                                new JProperty("returned","default"),
                                new JProperty("referenceTypes",null),
                                new JProperty("uniqueness","none")
                            },
                            new JObject()
                            {
                                new JProperty("name","version"),
                                new JProperty("description","The version of the resource being returned."),
                                new JProperty("type","string"),
                                new JProperty("caseExact",true),
                                new JProperty("multiValued",false),
                                new JProperty("mutability","readOnly"),
                                new JProperty("required",false),
                                new JProperty("returned","default"),
                                new JProperty("uniqueness","none")
                            }
                        })
                    }
                }),
                new JProperty("externalId",null),
                new JProperty("meta",new JArray()
                {
                    new JObject()
                    {
                        new JProperty("resourceType","Schema"),
                        new JProperty("created",DateTime.MinValue),
                        new JProperty("lastModified",DateTime.MinValue),
                        new JProperty("location",Url.Link("GetServiceProviderConfig", null)),
                        new JProperty("version","hogehoge")
                    }

                })
            };
        }
    }
}