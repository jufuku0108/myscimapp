using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MyScimApp.Data.Users;
using Newtonsoft.Json.Linq;
using MyScimApp.Extensions;
using IdentityServer4.EntityFramework.DbContexts;
using Microsoft.CodeAnalysis.Operations;
using IdentityServer4.Models;
using IdentityServer4.EntityFramework.Entities;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.AspNetCore.Authorization;
using MyScimApp.Models;
using Microsoft.EntityFrameworkCore;

namespace MyScimApp.Controllers
{
    [Authorize(Policy = "BearerOrBasicAuth")]
    [ApiController]
    public class ScimManageController : ControllerBase
    {
        private readonly ApplicationDbContext _applicationDbContext;
        private readonly ConfigurationDbContext _configurationDbContext;

        public ScimManageController(ApplicationDbContext applicationDbContext, ConfigurationDbContext configurationDbContext)
        {
            _applicationDbContext = applicationDbContext;
            _configurationDbContext = configurationDbContext;
        }

        [HttpGet]
        [Route("/v2/accesslogs")]
        public IActionResult GetAccessLogs()
        {
            try
            {
                // var accessLogs = _applicationDbContext.accessLogs.Where(al => al.DateTime >= DateTime.Now.AddDays(-7)).OrderByDescending(al => al.DateTime).ToList();
                // var accessLogs = _applicationDbContext.accessLogs.OrderByDescending(al => al.DateTime).Take(500);
                // var accessLogs = _applicationDbContext.accessLogs.ToList();
                var accessLogs = _applicationDbContext.accessLogs.Take(1000);
                return Ok(accessLogs);

            }
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }

        }
        [HttpDelete]
        [Route("/v2/accesslogs")]
        public IActionResult ClearAccessLogs()
        {
            try
            {
                // var result = _applicationDbContext.Database.ExecuteSqlRaw("USE [DB02]  DECLARE @return_value Int EXEC @return_value = [dbo].[TruncateAccessLogs] SELECT  @return_value as 'Return Value'");
                var result = _applicationDbContext.Database.ExecuteSqlRaw("EXECUTE dbo.TruncateAccessLogs");
                JObject jObject = new JObject
                {
                    new JProperty("result", "Success.")
                };
                return Ok(jObject);
            }
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }

        }


        [HttpGet]
        [Route("/v2/statistics")]
        public IActionResult GetStatistics()
        {
            try
            {
                var usersCount = _applicationDbContext.scimUsers.Count();
                var groupsCount = _applicationDbContext.scimGroups.Count();
                var accessLogs = new JArray();
                for (int i = -14; i <= 0; i++)
                {
                    var date = DateTime.Now.AddDays(i);
                    var startDate = new DateTime(date.Year, date.Month, date.Day);
                    var endDate = startDate.AddDays(1);
                    var accessLogCount = _applicationDbContext.accessLogs.Where(al => (al.DateTime >= startDate) && (al.DateTime < endDate)).ToList().Count();
                    var jObject = new JObject
                    {
                        new JProperty("date", startDate),
                        new JProperty("count", accessLogCount)
                    };
                    accessLogs.Add(jObject);
                }

                var statistics = new JObject
                {
                    new JProperty("usersCount", usersCount),
                    new JProperty("groupsCount", groupsCount),
                    new JProperty("accessLogs", accessLogs)
                };
                return Ok(statistics);

            }
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }
        }


        [HttpGet]
        [Route("/v2/clientapps")]
        public IActionResult GetClientApps()
        {
            try
            {
                var clientApps = _configurationDbContext.Clients.ToList();
                return Ok(clientApps);
            }
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }
        }
        [HttpPost]
        [Route("/v2/clientapps")]
        public IActionResult CreateClientApps([FromBody] JObject jObject)
        {
            try
            {
                var applicationName = (string)jObject["applicationName"];
                var applicationSecret = (string)jObject["applicationSecret"];
                var client = new IdentityServer4.Models.Client
                {
                    ClientId = Guid.NewGuid().ToString(),
                    ClientSecrets = { new IdentityServer4.Models.Secret(applicationSecret.Sha256()) },
                    ClientName = applicationName,
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AllowedScopes = {"scim.read.write" },
                    AccessTokenLifetime = 600
                };
                _configurationDbContext.Clients.Add(client.ToEntity());
                _configurationDbContext.SaveChanges();

                return Ok(client);
            }
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }
        }

        [HttpPost]
        [Route("/v2/authenticationcode")]
        public IActionResult GenerateAuthenticationCode()
        {
            try
            {
                var authenticationCode = new AuthenticationCode
                {
                    ExpiryDate = DateTime.UtcNow.AddDays(1),
                    Value = CreateRandomValue(100),
                    Active = true
                };
                _applicationDbContext.authenticationCodes.Add(authenticationCode);
                _applicationDbContext.SaveChanges();
                return Ok(authenticationCode);
            }
            catch (Exception exception)
            {
                var errorJobject = CommonFunctions.CreateErrorJobject(exception);
                Response.Headers.Add("Content-Type", "application/scim+json");

                return StatusCode(StatusCodes.Status500InternalServerError, errorJobject);
            }
        }



        private string CreateRandomValue(int length)
        {
            string validChars = "ABCDEFGHJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*?_-";
            Random random = new Random();
            char[] chars = new char[length];
            for(int i = 0; i < length; i++)
            {
                chars[i] = validChars[random.Next(0, validChars.Length)];
            }
            return new string(chars);

        }

    }
}