using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using MyScimApp.Data.Users;
using MyScimApp.Models;
using Newtonsoft.Json.Linq;
using System.Text;
using Microsoft.AspNetCore.Http;
using MyScimApp.Extensions;
using Microsoft.AspNetCore.Authorization;

namespace MyScimApp.Controllers
{
    [Authorize(Policy = "BearerOrBasicAuth")]
    [ApiController]
    public class ScimGroupController : ControllerBase
    {
        private readonly ApplicationDbContext _applicationDbContext;

        public ScimGroupController(ApplicationDbContext applicationDbContext)
        {
            _applicationDbContext = applicationDbContext;
        }

        [HttpPost]
        [Route("/v2/groups", Name = "CreateScimGroup")]
        public IActionResult CreateScimGroup([FromBody] JObject jObject)
        {
            try
            {

                var scimGroupId = Guid.NewGuid().ToString();
                var externalId = (string)jObject["externalId"];
                var displayName = (string)jObject["displayName"];
                JArray members = (JArray)jObject["members"];

                var creationTime = DateTime.UtcNow;
                var varsion = CommonFunctions.GetSHA256HashedString(creationTime.ToString());
                var etag = "W/\"" + varsion + "\"";


                var scimGroupMeta = new ScimGroupMetaData
                {
                    ResourceType = "urn:ietf:params:scim:schemas:core:2.0:Group",
                    Created = creationTime,
                    LastModified = creationTime,
                    Location = new Uri(this.Url.Link("GetScimGroupById", new { id = scimGroupId })).ToString(),
                    Version = etag
                };

                var scimGroup = new ScimGroup
                {
                    ScimGroupId = scimGroupId,
                    Schemas = new string[] { "urn:ietf:params:scim:schemas:core:2.0:Group" },
                    ExternalId = externalId,
                    DisplayName = displayName,
                    Members = new ScimGroupMember[] { }
                };
                scimGroup.Meta = scimGroupMeta;
                scimGroupMeta.ScimGroup = scimGroup;

                    _applicationDbContext.scimGroupMetaDatas.Add(scimGroupMeta);
                    _applicationDbContext.scimGroups.Add(scimGroup);
                    _applicationDbContext.SaveChanges();
 
                var createdScimGroup = _applicationDbContext.scimGroups.Where(sg => sg.ScimGroupId == scimGroupId).FirstOrDefault();
                var createdScimGroupMeta = _applicationDbContext.scimGroupMetaDatas.Where(sgm => sgm.ScimGroupId == scimGroupId).FirstOrDefault();
                createdScimGroup.Meta = createdScimGroupMeta;
                var returnedScimGroupJobject = CreateScimGroupJobject(createdScimGroup);
                var relativePath = createdScimGroup.Meta.Location;

                Response.Headers.Add("Etag", etag);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return Created(relativePath, returnedScimGroupJobject);
            }
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }

        }

        [HttpGet]
        [Route("/v2/groups" , Name = "GetScimGroups")]
        public IActionResult GetScimGroups(string filter)
        {
            try
            {
                if (string.IsNullOrEmpty(filter))
                {
                    var allScimGroups = _applicationDbContext.scimGroups.ToList();
                    JArray jArray = new JArray();
                    foreach (var perScimGroup in allScimGroups)
                    {
                        perScimGroup.Schemas = new string[] { "urn:ietf:params:scim:schemas:core:2.0:Group" };
                        var scimGroupMeta = _applicationDbContext.scimGroupMetaDatas.Where(sgm => sgm.ScimGroupId == perScimGroup.ScimGroupId).FirstOrDefault();
                        perScimGroup.Meta = scimGroupMeta;
                        var perScimGroupMembers = _applicationDbContext.scimGroupMembers.Where(sgm => sgm.ScimGroupId == perScimGroup.ScimGroupId).ToList();
                        if (perScimGroupMembers.Count == 0)
                        {
                            perScimGroup.Members = new ScimGroupMember[] { };
                        }
                        else
                        {
                            perScimGroup.Members = perScimGroupMembers;
                        }

                        var returnedScimGroupJobject = CreateScimGroupJobject(perScimGroup);
                        jArray.Add(returnedScimGroupJobject);
                    }
                    Response.Headers.Add("Content-Type", "application/scim+json");

                    return Ok(jArray);
                }

                var elements = filter.Split(" ");
                var attribute = elements[0];
                var value = elements[2].Replace("\"", "");
                var scimGroup = _applicationDbContext.scimGroups.Where(sg => sg.DisplayName == value).FirstOrDefault();
                
                if(scimGroup != null)
                {
                    var scimGroupMeta = _applicationDbContext.scimGroupMetaDatas.Where(sgm => sgm.ScimGroupId == scimGroup.ScimGroupId).FirstOrDefault();
                    scimGroup.Meta = scimGroupMeta;
                    var scimGroupMembers = _applicationDbContext.scimGroupMembers.Where(sgm => sgm.ScimGroupId == scimGroup.ScimGroupId).ToList();
                    if (scimGroupMembers.Count == 0)
                    {
                        scimGroup.Members = new ScimGroupMember[] { };
                    }
                    else
                    {
                        scimGroup.Members = scimGroupMembers;
                    }
                    scimGroup.Schemas = new string[] { "urn:ietf:params:scim:schemas:core:2.0:Group" };

                    var returnedScimGroupJobject = CreateScimGroupJobject(scimGroup);
                    var returnedFilteredJobject = CommonFunctions.CreateFilteredJobject(returnedScimGroupJobject);
                    Response.Headers.Add("Content-Type", "application/scim+json");

                    return Ok(returnedFilteredJobject);
                }
                else
                {
                    var clearJobject = new JObject { };
                    var returnedFilteredJobject = CommonFunctions.CreateFilteredJobject(clearJobject);
                    Response.Headers.Add("Content-Type", "application/scim+json");
                    return Ok(returnedFilteredJobject);
                }
            }
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }
        }


        [HttpGet]
        [Route("/v2/groups/{id:guid}", Name = "GetScimGroupById")]
        public IActionResult GetScimGroupById(string id)
        {
            try
            {
                var scimGroup = _applicationDbContext.scimGroups.Where(sg => sg.ScimGroupId == id).FirstOrDefault();
                scimGroup.Schemas = new string[] { "urn:ietf:params:scim:schemas:core:2.0:Group" };
                var scimGroupMeta = _applicationDbContext.scimGroupMetaDatas.Where(sgm => sgm.ScimGroupId == id).FirstOrDefault();
                scimGroup.Meta = scimGroupMeta;
                var scimGroupMembers = _applicationDbContext.scimGroupMembers.Where(sgm => sgm.ScimGroupId == id).ToList();
                if (scimGroupMembers.Count == 0)
                {
                    scimGroup.Members = new ScimGroupMember[] { };
                }
                else
                {
                    scimGroup.Members = scimGroupMembers;
                }

                var returnedScimGroupJobject = CreateScimGroupJobject(scimGroup);

                var relativePath = scimGroup.Meta.Location;
                Response.Headers.Add("Location", relativePath);
                Response.Headers.Add("Etag", scimGroup.Meta.Version);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return Ok(returnedScimGroupJobject);

            }
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }

        }



        [HttpPatch]
        [Route("/v2/groups/{id:guid}", Name = "UpdateScimGroupById")]
        public IActionResult UpdateScimGroupById(string id, [FromBody]JObject jObject)
        {
            try
            {
                var scimGroup = _applicationDbContext.scimGroups.Where(sg => sg.ScimGroupId == id).FirstOrDefault();
                JArray jArray = (JArray)jObject["Operations"];
                foreach (JObject jo in jArray)
                {
                    var operation = (string)jo["op"];
                    var path = (string)jo["path"];
                    switch (operation)
                    {
                        case "Add":
                            switch (path)
                            {
                                case "members":
                                    var members = jo["value"];
                                    foreach (var member in members)
                                    {

                                        var insertScimUserId = (string)member["value"];
                                        var insertScimUser = _applicationDbContext.scimUsers.Where(su => su.ApplicationUserId == insertScimUserId).FirstOrDefault();

                                        var insertGroupMember = new ScimGroupMember
                                        {
                                            Display = insertScimUser.DisplayName,
                                            Value = insertScimUser.ApplicationUserId,
                                            Reference = new Uri(this.Url.Link("GetScimUserById", new { id = insertScimUser.ApplicationUserId })).ToString(),
                                            ScimGroupId = scimGroup.ScimGroupId,
                                            ScimGroup = scimGroup
                                        };
                                        _applicationDbContext.scimGroupMembers.Add(insertGroupMember);

                                    }
                                    break;
                            }
                            break;
                        case "Remove":
                            switch (path)
                            {
                                case "members":
                                    var members = jo["value"];
                                    foreach (var member in members)
                                    {
                                        var removeScimUserId = (string)member["value"];
                                        var removeScimGroupMembers = _applicationDbContext.scimGroupMembers.Where(sgm => sgm.ScimGroupId == id);
                                        var removeScimGroupMember = removeScimGroupMembers.Where(sgm => sgm.Value == removeScimUserId).FirstOrDefault();
                                        _applicationDbContext.scimGroupMembers.Remove(removeScimGroupMember);
                                    }
                                    break;
                            }
                            break;
                    }
                }

                var scimGroupMeta = _applicationDbContext.scimGroupMetaDatas.Where(sgm => sgm.ScimGroupId == id).FirstOrDefault();
                var lastModified = DateTime.UtcNow;
                var varsion = CommonFunctions.GetSHA256HashedString(lastModified.ToString());
                var etag = "W/\"" + varsion + "\"";
                scimGroupMeta.LastModified = lastModified;
                scimGroupMeta.Version = etag;

                _applicationDbContext.scimGroupMetaDatas.Update(scimGroupMeta);
                _applicationDbContext.SaveChanges();

                scimGroup.Schemas = new string[] { "urn:ietf:params:scim:schemas:core:2.0:Group" };
                scimGroup.Meta = scimGroupMeta;
                var updatedScimGroupMembers = _applicationDbContext.scimGroupMembers.Where(sgm => sgm.ScimGroupId == id).ToList();
                if (updatedScimGroupMembers.Count == 0)
                {
                    scimGroup.Members = new ScimGroupMember[] { };
                }
                else
                {
                    scimGroup.Members = updatedScimGroupMembers;
                }

                var returnedScimGroupJobject = CreateScimGroupJobject(scimGroup);
                var relativePath = scimGroup.Meta.Location;
                Response.Headers.Add("Location", relativePath);
                Response.Headers.Add("Etag", scimGroup.Meta.Version);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return Ok(returnedScimGroupJobject);
            } 
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }
        }

        [HttpDelete]
        [Route("/v2/groups/{id:guid}", Name = "DeleteScimGroupById")]
        public IActionResult DeleteScimGroupById(string id)
        {
            try
            {
                var deleteScimGroup = _applicationDbContext.scimGroups.Where(sg => sg.ScimGroupId == id).FirstOrDefault();
                var deleteScimGroupMeta = _applicationDbContext.scimGroupMetaDatas.Where(sgm => sgm.ScimGroupId == id).FirstOrDefault();
                var deleteScimGroupMembers = _applicationDbContext.scimGroupMembers.Where(sgm => sgm.ScimGroupId == id).ToList();
                if (deleteScimGroupMembers.Count != 0)
                {
                    deleteScimGroup.Members = deleteScimGroupMembers;
                    _applicationDbContext.scimGroupMembers.RemoveRange(deleteScimGroupMembers);
                }
                deleteScimGroup.Meta = deleteScimGroupMeta;
                _applicationDbContext.scimGroups.Remove(deleteScimGroup);
                _applicationDbContext.scimGroupMetaDatas.Remove(deleteScimGroupMeta);
                _applicationDbContext.SaveChanges();

                return NoContent();
            }
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }
        }



        private JObject CreateScimGroupJobject(ScimGroup scimGroup)
        {
            JArray membersJarray = new JArray();
            var scimGroupMembers = scimGroup.Members;
            foreach (var scimGroupMember in scimGroupMembers)
            {
                JObject jobt = new JObject()
                {
                    new JProperty("value",scimGroupMember.Value),
                    new JProperty("$ref",scimGroupMember.Reference),
                    new JProperty("display",scimGroupMember.Display)
                };
                membersJarray.Add(jobt);
            }
            JObject jObject = new JObject
            {
                new JProperty("schemas",new JArray(scimGroup.Schemas.FirstOrDefault())),
                new JProperty("id",scimGroup.ScimGroupId),
                new JProperty("externalId",scimGroup.ExternalId),
                new JProperty("displayName",scimGroup.DisplayName),
                new JProperty("members",membersJarray),
                new JProperty("meta",new JObject
                {
                    new JProperty("resourceType",scimGroup.Meta.ResourceType),
                    new JProperty("created",scimGroup.Meta.Created),
                    new JProperty("lastModified",scimGroup.Meta.LastModified),
                    new JProperty("location",scimGroup.Meta.Location),
                    new JProperty("version",scimGroup.Meta.Version)
                }),
            };
            return jObject;
        }



    }
}