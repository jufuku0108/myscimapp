using IdentityServer4.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.IdentityModel;

namespace MyScimApp.Extensions
{
    public static class IdentityServerConfig
    {

        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
                //new IdentityResource(name:"scim", userClaims: new[]{"scim_id","scim_location"},displayName:"Your SCIM resource.")

            };
        }

        public static IEnumerable<ApiResource> GetApiResources(IApplicationBuilder applicationBuilder)
        {
            var configuration = applicationBuilder.ApplicationServices.GetService<IConfiguration>();
            var scimAPI = configuration["MyScimAPI"];

            return new List<ApiResource>
            {
                new ApiResource(scimAPI, "My SCIM API") {Scopes = { "me", "users.read", "users.read.write", "groups.read", "groups.read.write", "system.read" }},
            };
        }

        public static IEnumerable<ApiScope> GetApiScopes()
        {
            return new List<ApiScope>
            {
                new ApiScope(name: "me", displayName: "Read my profile data using SCIM."),
                new ApiScope(name: "users.read", displayName: "Read users resources using SCIM."),
                new ApiScope(name: "users.read.write", displayName: "Read and Write users resources using SCIM."),
                new ApiScope(name: "groups.read", displayName: "Read groups resources using SCIM."),
                new ApiScope(name: "groups.read.write", displayName: "Read and Write groups resources using SCIM."),
                new ApiScope(name: "system.read", displayName: "Read System data.")

            };
        }

        public static IEnumerable<Client> GetClients(IApplicationBuilder applicationBuilder)
        {
            var configuration = applicationBuilder.ApplicationServices.GetService<IConfiguration>();

            var myScimAppClientId = configuration["MyScimAppClientId"];
            var myScimAppClientSecret = configuration["MyScimAppClientSecret"];

            var myAdminPortalClientId = configuration["MyAdminPortalClientId"];
            var myAdminPortalClientSecret = configuration["MyAdminPortalClientSecret"];
            var myAdminPortalRedirectUri = configuration["MyAdminPortalRedirectUri"];
            var myAdminPortalLogoutUri = configuration["MyAdminPortalLogoutUri"];

            return new List<Client>
            {

                new Client
                {
                    ClientName = "MyScimApp",
                    ClientId = myScimAppClientId,
                    ClientSecrets = {new Secret(myScimAppClientSecret.Sha256()) },
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AllowedScopes = { "users.read.write", "groups.read.write" },
                    RequireConsent = false,
                    Description = "System"
                },
                new Client
                {
                    ClientName = "MyAdminPortal",
                    ClientId = myAdminPortalClientId,
                    ClientSecrets = {new Secret(myAdminPortalClientSecret.Sha256()) },
                    AllowedGrantTypes = GrantTypes.Code,
                    AllowedScopes = { "openid", "email", "profile", "offline_access", "users.read", "groups.read", "system.read" },
                    RequireConsent = false,
                    AllowOfflineAccess = true,
                    Description = "System",
                    RedirectUris = new []{ myAdminPortalRedirectUri },
                    FrontChannelLogoutUri = myAdminPortalLogoutUri,
                    BackChannelLogoutUri = myAdminPortalLogoutUri,
                    RequirePkce = false,
                    AccessTokenLifetime = 3600,
                    AbsoluteRefreshTokenLifetime = 86400,

                }

            };
        }
    }
}
