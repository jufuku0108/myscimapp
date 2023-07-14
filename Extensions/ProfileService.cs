using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Identity;
using MyScimApp.Models;
using IdentityServer4.Models;
using IdentityServer4.Extensions;
using System.Security.Claims;

namespace MyScimApp.Extensions
{
    public class ProfileService : IProfileService
    {
        protected UserManager<ApplicationUser> _userManager;
        public ProfileService(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }
        public async Task GetProfileDataAsync(ProfileDataRequestContext profileDataRequestContext)
        {
            if(profileDataRequestContext.Caller == "ClaimsProviderIdentityToken")
            {
                // Edit Id token
                var scimScope = profileDataRequestContext.RequestedResources.ParsedScopes.AsQueryable().Where(c => c.ParsedName == "scim").FirstOrDefault();
                if (scimScope != null)
                {
                    var user = await _userManager.GetUserAsync(profileDataRequestContext.Subject);
                    var claims = await _userManager.GetClaimsAsync(user);
                    profileDataRequestContext.IssuedClaims.AddRange(claims);
                }

            }
            else if (profileDataRequestContext.Caller == "ClaimsProviderAccessToken")
            {
                // Edit Access token
                /*
                var user = await _userManager.GetUserAsync(profileDataRequestContext.Subject);
                var claims = new List<Claim>
                {
                    new Claim("fullName", "hogehoge")
                };
                profileDataRequestContext.IssuedClaims.AddRange(claims);
                 */

            }


        }
        public async Task IsActiveAsync(IsActiveContext isActiveContext)
        {
            var user = await _userManager.GetUserAsync(isActiveContext.Subject);
            isActiveContext.IsActive = (user != null);
        }
    }
}
