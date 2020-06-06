using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.VisualBasic;
using MyScimApp.Models;
using Newtonsoft.Json.Linq;
using Microsoft.AspNetCore.Http;
using MyScimApp.Data.Users;
using MyScimApp.Extensions;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Authorization;
using IdentityServer4.AccessTokenValidation;

namespace MyScimApp.Controllers
{
    [Authorize(Policy = "BearerOrBasicAuth")]
    [ApiController]
    public class ScimUserController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _applicationDbContext;

        public ScimUserController(UserManager<ApplicationUser> userManager, ApplicationDbContext applicationDbContext)
        {
            _userManager = userManager;
            _applicationDbContext = applicationDbContext;
        }

        [HttpPost]
        [Route("/v2/users", Name = "CreateScimUser")]
        public async Task<IActionResult> CreateScimUser([FromBody] JObject jObject)
        {
            try
            {
                var applicationUser = CreateApplicationUserObject(jObject);

                var scimUser = CreateScimUserObject(jObject);
                var scimUserName = CreateScimUserNameObject(jObject);
                var scimUserPhoneNumbers = CreateScimUserPhoneNumberObjects(jObject);
                var scimUserEmails = CreateScimUserEmailObjects(jObject);
                var scimUserMetaData = CreateScimUserMetaDataObject(jObject);

                applicationUser.ScimUser = new ScimUser[] { scimUser };
                scimUser.ApplicationUser = applicationUser;

                scimUser.Name = scimUserName;
                scimUserName.ScimUser = scimUser;

                scimUser.PhoneNumbers = scimUserPhoneNumbers;
                foreach (var scimUserPhoneNumber in scimUserPhoneNumbers)
                {
                    scimUserPhoneNumber.ScimUser = scimUser;
                }

                scimUser.Emails = scimUserEmails;
                foreach (var scimUserEmail in scimUserEmails)
                {
                    scimUserEmail.ScimUser = scimUser;
                }


                scimUserMetaData.Location = new Uri(this.Url.Link("GetScimUserById", new { id = applicationUser.Id })).ToString();
                scimUser.Meta = scimUserMetaData;
                scimUserMetaData.ScimUser = scimUser;

                var appUserResult = await _userManager.CreateAsync(applicationUser);
                if (appUserResult.Succeeded)
                {

                    var createdUser = await _userManager.FindByNameAsync(applicationUser.UserName);
                    var createdScimUser = createdUser.ScimUser.FirstOrDefault();
                    var returnedUserJobject = CreateScimUserJobject(createdScimUser);
                    var relativePath = createdScimUser.Meta.Location;

                    Response.Headers.Add("Etag", createdScimUser.Meta.Version);
                    Response.Headers.Add("Content-Type", "application/scim+json");
                    return Created(relativePath, returnedUserJobject);
                }
                throw new Exception();

            }
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }


        }

        [HttpGet]
        [Route("/v2/users", Name = "GetScimUsers")]
        public IActionResult GetScimUsers([FromQuery] string filter)
       {
            try
            {
                if (string.IsNullOrEmpty(filter))
                {
                    var allScimUsers = _applicationDbContext.scimUsers.ToList();
                    JArray jArray = new JArray();
                    foreach (var perScimUser in allScimUsers)
                    {
                        var perScimUserName = _applicationDbContext.scimUserNames.Where(sun => sun.ScimUserId == perScimUser.ScimUserId).FirstOrDefault(); ;
                        var perScimUserPhoneNumber = _applicationDbContext.scimUserPhoneNumbers.Where(sup => sup.ScimUserId == perScimUser.ScimUserId).ToList();
                        var perScimUserEmail = _applicationDbContext.scimUserEmails.Where(sue => sue.ScimUserId == perScimUser.ScimUserId).ToList();
                        var perScimUserMetaData = _applicationDbContext.scimUserMetaDatas.Where(sum => sum.ScimUserId == perScimUser.ScimUserId).FirstOrDefault();

                        perScimUser.Schemas = new string[] { "urn:ietf:params:scim:schemas:core:2.0:User" };
                        perScimUser.Roles = new string[] { };
                        perScimUser.Name = perScimUserName;
                        perScimUser.PhoneNumbers = perScimUserPhoneNumber;
                        perScimUser.Emails = perScimUserEmail;
                        perScimUser.Meta = perScimUserMetaData;

                        var returnedUserJobject = CreateScimUserJobject(perScimUser);
                        jArray.Add(returnedUserJobject);
                    }
                    Response.Headers.Add("Content-Type", "application/scim+json");

                    return Ok(jArray);

                }

                var elements = filter.Split(" ");
                var attribute = elements[0];
                var value = elements[2].Replace("\"", "");

                var scimUser = _applicationDbContext.scimUsers.Where(su => su.UserName == value).FirstOrDefault();

                if(scimUser != null)
                {
                    var scimUserName = _applicationDbContext.scimUserNames.Where(sun => sun.ScimUserId == scimUser.ScimUserId).FirstOrDefault(); ;
                    var scimUserPhoneNumber = _applicationDbContext.scimUserPhoneNumbers.Where(sup => sup.ScimUserId == scimUser.ScimUserId).ToList();
                    var scimUserEmail = _applicationDbContext.scimUserEmails.Where(sue => sue.ScimUserId == scimUser.ScimUserId).ToList();
                    var scimUserMetaData = _applicationDbContext.scimUserMetaDatas.Where(sum => sum.ScimUserId == scimUser.ScimUserId).FirstOrDefault();

                    scimUser.Schemas = new string[] { "urn:ietf:params:scim:schemas:core:2.0:User" };
                    scimUser.Roles = new string[] { };
                    scimUser.Name = scimUserName;
                    scimUser.PhoneNumbers = scimUserPhoneNumber;
                    scimUser.Emails = scimUserEmail;
                    scimUser.Meta = scimUserMetaData;

                    var returnedUserJobject = CreateScimUserJobject(scimUser);
                    var returnedFilteredJobject = CommonFunctions.CreateFilteredJobject(returnedUserJobject);

                    Response.Headers.Add("Location", scimUser.Meta.Location);
                    Response.Headers.Add("Etag", scimUser.Meta.Version);
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
        [Route("/v2/users/{id:guid}", Name = "GetScimUserById")]
        public IActionResult GetScimUserById(string id)
        {
            try
            {
                var scimUser = _applicationDbContext.scimUsers.Where(su => su.ApplicationUserId == id).FirstOrDefault();
                
                var scimUserName = _applicationDbContext.scimUserNames.Where(sun => sun.ScimUserId == scimUser.ScimUserId).FirstOrDefault();
                var scimUserPhoneNumber = _applicationDbContext.scimUserPhoneNumbers.Where(sup => sup.ScimUserId == scimUser.ScimUserId).ToList();
                var scimUserEmail = _applicationDbContext.scimUserEmails.Where(sue => sue.ScimUserId == scimUser.ScimUserId).ToList();
                var scimUserMetaData = _applicationDbContext.scimUserMetaDatas.Where(sum => sum.ScimUserId == scimUser.ScimUserId).FirstOrDefault();

                scimUser.Schemas = new string[] { "urn:ietf:params:scim:schemas:core:2.0:User" };
                scimUser.Roles = new string[] { };
                scimUser.Name = scimUserName;
                scimUser.PhoneNumbers = scimUserPhoneNumber;
                scimUser.Emails = scimUserEmail;
                scimUser.Meta = scimUserMetaData;

                var returnedUserJobject = CreateScimUserJobject(scimUser);

                Response.Headers.Add("Location", scimUser.Meta.Location);
                Response.Headers.Add("Etag", scimUser.Meta.Version);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return Ok(returnedUserJobject);

            }
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }

        }

        [HttpPatch]
        [Route("/v2/users/{id:guid}", Name = "UpdateScimUserById")]
        public IActionResult UpdateScimUserById(string id, [FromBody] JObject jObject)
        {
            try
            {
                var scimUser = _applicationDbContext.scimUsers.Where(su => su.ApplicationUserId == id).FirstOrDefault();
                scimUser.Schemas = new string[] { "urn:ietf:params:scim:schemas:core:2.0:User" };
                scimUser.Roles = new string[] { };
                scimUser.UserType = "ScimUser";

                JArray jArray = (JArray)jObject["Operations"];
                foreach (JObject jo in jArray)
                {
                    var operation = (string)jo["op"];
                    var path = (string)jo["path"];
                    var value = (string)jo["value"];
                    switch (operation)
                    {
                        case "Add":
                            switch (path)
                            {
                                case "displayName":
                                    scimUser.DisplayName = value;
                                    break;
                                case "emails[type eq \"work\"].value":
                                    var newScimUserEmail = new ScimUserEmail
                                    {
                                        Type = "work",
                                        Primary = false,
                                        Value = value,
                                        ScimUserId = scimUser.ScimUserId,
                                        ScimUser = scimUser
                                    };
                                    _applicationDbContext.scimUserEmails.Add(newScimUserEmail);
                                    break;
                            }

                            break;
                        case "Replace":
                            switch (path)
                            {
                                case "active":
                                    var boolean = (bool)jo["value"];
                                    scimUser.Active = boolean;
                                    break;
                            }
                            break;

                    }
                }
                var scimUserMeta = _applicationDbContext.scimUserMetaDatas.Where(sum => sum.ScimUserId == scimUser.ScimUserId).FirstOrDefault();
                var lastModified = DateTime.UtcNow;
                var varsion = CommonFunctions.GetSHA256HashedString(lastModified.ToString());
                var etag = "W/\"" + varsion + "\"";
                scimUserMeta.LastModified = lastModified;
                scimUserMeta.Version = etag;

                _applicationDbContext.scimUsers.Update(scimUser);
                _applicationDbContext.scimUserMetaDatas.Update(scimUserMeta);
                _applicationDbContext.SaveChanges();


                var updatedScimUser = _applicationDbContext.scimUsers.Where(su => su.ApplicationUserId == id).FirstOrDefault();

                updatedScimUser.Schemas = new string[] { "urn:ietf:params:scim:schemas:core:2.0:User" };
                updatedScimUser.Roles = new string[] { };

                var updatedScimUserName = _applicationDbContext.scimUserNames.Where(sun => sun.ScimUserId == scimUser.ScimUserId).FirstOrDefault();
                var updatedScimUserPhoneNumber = _applicationDbContext.scimUserPhoneNumbers.Where(sup => sup.ScimUserId == scimUser.ScimUserId).ToList();
                var updatedScimUserEmail = _applicationDbContext.scimUserEmails.Where(sue => sue.ScimUserId == scimUser.ScimUserId).ToList();
                var updatedScimUserMetaData = _applicationDbContext.scimUserMetaDatas.Where(sum => sum.ScimUserId == scimUser.ScimUserId).FirstOrDefault();

                updatedScimUser.Name = updatedScimUserName;
                updatedScimUser.PhoneNumbers = updatedScimUserPhoneNumber;
                updatedScimUser.Emails = updatedScimUserEmail;
                updatedScimUser.Meta = updatedScimUserMetaData;

                var returnedUserJobject = CreateScimUserJobject(scimUser);

                Response.Headers.Add("Location", scimUser.Meta.Location);
                Response.Headers.Add("Etag", scimUser.Meta.Version);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return Ok(returnedUserJobject);

            }
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }
        }

        [HttpDelete]
        [Route("/v2/users/{id:guid}", Name = "DeleteScimUserById")]
        public async Task<IActionResult> DeleteScimUserById(string id)
        {
            try
            {
                var applicationUser = await _userManager.FindByIdAsync(id);
                var applicationUserRemoveResult = await _userManager.DeleteAsync(applicationUser);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return NoContent();
            }
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }
        }

        private JObject CreateScimUserJobject(ScimUser scimUser)
        {

            JArray emailsJarray = new JArray();
            var emails = scimUser.Emails;
            foreach (var email in emails)
            {
                JObject jobt = new JObject()
                {
                    new JProperty("type",email.Type),
                    new JProperty("value",email.Value),
                    new JProperty("primary",email.Primary)
                };
                emailsJarray.Add(jobt);
            }

            JArray phonesJarray = new JArray();
            var phones = scimUser.PhoneNumbers;
            foreach (var phone in phones)
            {
                JObject jobt = new JObject()
                {
                    new JProperty("type",phone.Type),
                    new JProperty("value",phone.Value),
                };
                phonesJarray.Add(jobt);
            }

            JObject jObject = new JObject
            {
                new JProperty("schemas",new JArray(scimUser.Schemas[0])),
                new JProperty("id",scimUser.ApplicationUserId),
                new JProperty("externalId",scimUser.ExternalId),
                new JProperty("meta",new JObject
                {
                    new JProperty("resourceType",scimUser.Meta.ResourceType),
                    new JProperty("created",scimUser.Meta.Created),
                    new JProperty("lastModified",scimUser.Meta.LastModified),
                    new JProperty("location",scimUser.Meta.Location),
                    new JProperty("version",scimUser.Meta.Version)
                }),
                new JProperty("name",new JObject
                {
                    new JProperty("formatted",scimUser.Name.Formatted),
                    new JProperty("familyName",scimUser.Name.FamilyName),
                    new JProperty("givenName",scimUser.Name.GivenName)
                }),
                new JProperty("userName",scimUser.UserName),
                new JProperty("displayName",scimUser.DisplayName),
                new JProperty("phoneNumbers",phonesJarray),
                new JProperty("emails",emailsJarray),
                new JProperty("active",scimUser.Active),
                new JProperty("userType",scimUser.UserType),
            };
            return jObject;

        }

        private ApplicationUser CreateApplicationUserObject(JObject jObject)
        {
            return new ApplicationUser
            {
                UserName = (string)jObject["userName"],
                Email = (string)jObject["userName"],
                UserType = "ScimUser"
            };
        }
        private ScimUser CreateScimUserObject(JObject jObject)
        {
            return new ScimUser
            {
                Schemas = new string[] { "urn:ietf:params:scim:schemas:core:2.0:User" },
                UserName = (string)jObject["userName"],
                ExternalId = (string)jObject["externalId"],
                Active = (bool)jObject["active"],
                Roles = new string[] { },
                DisplayName = (string)jObject["displayName"],
                UserType = "ScimUser"
            };

        }
        private ScimUserName CreateScimUserNameObject(JObject jObject)
        {

            JToken tokenName = jObject["name"];
            if (tokenName != null)
            {
                return new ScimUserName
                {
                    Formatted = (string)jObject["name"]["formatted"],
                    FamilyName = (string)jObject["name"]["familyName"],
                    GivenName = (string)jObject["name"]["givenName"],
                };
            }
            else
            {
                return new ScimUserName { };
            }


        }
        private IList<ScimUserPhoneNumber> CreateScimUserPhoneNumberObjects(JObject jObject)
        {
            IList<ScimUserPhoneNumber> scimUserPhoneNumbers = new List<ScimUserPhoneNumber>();
            var phones = jObject["phoneNumbers"];

            if (phones != null)
            {
                foreach(var phone in phones)
                {
                    var scimUserPhoneNumber = new ScimUserPhoneNumber
                    {
                        Type = (string)phone["type"],
                        Value = (string)phone["value"]
                    };
                    scimUserPhoneNumbers.Add(scimUserPhoneNumber);
                }
            }
            return scimUserPhoneNumbers;

        }
        private IList<ScimUserEmail> CreateScimUserEmailObjects(JObject jObject)
        {
            IList<ScimUserEmail> scimUserEmails = new List<ScimUserEmail>();
            var emails = jObject["emails"];

            if (emails != null)
            {
                foreach(var email in emails)
                {
                    var scimUserEmail = new ScimUserEmail
                    {
                        Primary = (bool)email["primary"],
                        Type = (string)email["type"],
                        Value = (string)email["value"]
                    };
                    scimUserEmails.Add(scimUserEmail);
                }
            }
            return scimUserEmails;
        }
        private ScimUserMetaData CreateScimUserMetaDataObject(JObject jObject)
        {
            var creationTime = DateTime.UtcNow;
            var varsion = CommonFunctions.GetSHA256HashedString(creationTime.ToString());
            var etag = "W/\"" + varsion + "\"";

            return new ScimUserMetaData
            {
                ResourceType = "User",
                Created = DateTime.UtcNow,
                LastModified = DateTime.UtcNow,
                Version = etag
            };
            
        }
    }
}