using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Net.Http.Headers;
using System.Text;
using System.Security.Claims;
using MyScimApp.Data.Users;

namespace MyScimApp.Extensions
{
    public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly ApplicationDbContext _applicationDbContext;
        public BasicAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ApplicationDbContext applicationDbContext): base(options, logger, encoder, clock)
        {
            _applicationDbContext = applicationDbContext;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            try
            {
                
                if (!Request.Headers.ContainsKey("Authorization"))
                {
                    return AuthenticateResult.Fail("Missing Authorization Header");
                }

                var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
                var code = authHeader.Parameter;
                var applicationCode = _applicationDbContext.authenticationCodes.Where(ac => ac.Value == code).FirstOrDefault();
        
                if (applicationCode == null)
                {
                    return AuthenticateResult.Fail("Provided code could not find.");
                }
                if (!applicationCode.Active)
                {
                    return AuthenticateResult.Fail("Provided code is disabled.");
                }

                if (applicationCode.ExpiryDate <= DateTime.UtcNow)
                {
                    applicationCode.Active = false;
                    await _applicationDbContext.SaveChangesAsync();
                    return AuthenticateResult.Fail("Provided code is expired.");
                }

                var claims = new[] {
                    new Claim(ClaimTypes.NameIdentifier, applicationCode.AuthenticationCodeId.ToString()),
                    new Claim(ClaimTypes.Name, applicationCode.AuthenticationCodeId.ToString())
                };
                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);


                return AuthenticateResult.Success(ticket);
            }
            catch
            {
                return AuthenticateResult.Fail("Invalid Authorization Atempt.");
            }
        }
    }
}
