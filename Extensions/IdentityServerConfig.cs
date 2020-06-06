using IdentityServer4.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

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
                new IdentityResources.Email()
            };
        }

        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource("scimapi", "Scim Apis") {Scopes = {new Scope("scim.read.write")}}
            };
        }

        public static IEnumerable<Client> GetClients(IApplicationBuilder applicationBuilder)
        {
            var configuration = applicationBuilder.ApplicationServices.GetService<IConfiguration>();

            var myPortalDevelopment = configuration["MyPortalDevelopment"];
            var myPortalDevelopmentClientId = configuration["MyPortalDevelopmentClientId"];

            var myPortalProduction = configuration["MyPortalProduction"];
            var myPortalProductionClientId = configuration["MyPortalProductionClientId"];

            return new List<Client>
            {
                new Client
                {
                    ClientId = myPortalDevelopmentClientId,
                    ClientName = "My portal",

                    AllowedGrantTypes = GrantTypes.Code,
                    RequirePkce = true,
                    RequireClientSecret = false,
                    AllowAccessTokensViaBrowser = true,

                    RedirectUris =
                    {
                        myPortalDevelopment + "/auth-callback",
                        myPortalDevelopment + "/auth-callback.html",
                        myPortalDevelopment + "/silent-renew",
                        myPortalDevelopment + "/silent-renew.html"
                    },

                    PostLogoutRedirectUris = { myPortalDevelopment },
                    AllowedCorsOrigins = { myPortalDevelopment },

                    AllowedScopes = { "openid", "profile", "email", "scim.read.write" },
                    RequireConsent = false,
                    AccessTokenLifetime = 240

                },
                new Client
                {
                    ClientId = myPortalProductionClientId,
                    ClientName = "My portal",

                    AllowedGrantTypes = GrantTypes.Code,
                    RequirePkce = true,
                    RequireClientSecret = false,
                    AllowAccessTokensViaBrowser = true,

                    RedirectUris =
                    {
                        myPortalProduction + "/auth-callback",
                        myPortalProduction + "/auth-callback.html",
                        myPortalProduction + "/silent-renew",
                        myPortalProduction + "/silent-renew.html"
                    },

                    PostLogoutRedirectUris = { myPortalProduction },
                    AllowedCorsOrigins = { myPortalProduction },

                    AllowedScopes = { "openid", "profile", "email", "scim.read.write" },
                    RequireConsent = false,
                    AccessTokenLifetime = 1800

                }
            };
        }
    }
}
