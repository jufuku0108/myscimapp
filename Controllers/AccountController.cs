using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MyScimApp.Models;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using IdentityModel.Client;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Models;
using System.Text;
using System.Net.Http;
using Microsoft.AspNetCore.Authentication.Twitter;
using System.Runtime.InteropServices.WindowsRuntime;
using MyScimApp.Extensions;
using MyScimApp.Data.Users;
using Microsoft.AspNetCore.Authorization;
using System.Globalization;
using Microsoft.Extensions.Caching.Distributed;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json.Linq;
using Microsoft.Identity.Client;
using Microsoft.Graph;
using IdentityModel;
using System.Web;
using IdentityServer4.EntityFramework.DbContexts;

namespace MyScimApp.Controllers
{
    public class AccountController : Controller
    {
        [TempData]
        public string UniqueId { get; set; }

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly ApplicationDbContext _applicationDbContext;
        private readonly Fido2Service _fido2Service;
        private readonly IDistributedCache _distributedCache;
        private Fido2 _fido2;
        private IConfiguration _configuration;
        private ConfigurationDbContext _configurationDbContext;

        public AccountController(
            UserManager<ApplicationUser> userManager, 
            SignInManager<ApplicationUser> signInManager, 
            IIdentityServerInteractionService interaction, 
            ApplicationDbContext applicationDbContext,
            Fido2Service fido2Service,
            IDistributedCache distributedCache,
            IConfiguration configuration,
            ConfigurationDbContext configurationDbContext)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _interaction = interaction;
            _applicationDbContext = applicationDbContext;
            _fido2Service = fido2Service;
            _distributedCache = distributedCache;
            _configuration = configuration;
            _fido2 = new Fido2(new Fido2Configuration()
            {
                ServerDomain = _configuration["Fido2ServerDomain"],
                ServerName = "MyScimApp",
                Origin = _configuration["Fido2Origin"]
            });
            _configurationDbContext = configurationDbContext;
        }

        [HttpGet]
        public IActionResult Login(string userName, string returnUrl)
        {
            var loginViewModel = new LoginViewModel();
            loginViewModel.Username = userName;
            loginViewModel.ReturnUrl = returnUrl;
            return View(loginViewModel);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel loginViewModel)
        {
            if (ModelState.IsValid)
            {

                var signinResult = await _signInManager.PasswordSignInAsync(loginViewModel.Username, loginViewModel.Password, loginViewModel.RememberLogin, lockoutOnFailure: true);
                if (signinResult.Succeeded)
                {
                    if (Url.IsLocalUrl(loginViewModel.ReturnUrl))
                    {
                        return Redirect(loginViewModel.ReturnUrl);
                    }
                    return RedirectToAction("Index", "Home");
                }
                else if (signinResult.RequiresTwoFactor)
                {
                        return RedirectToAction("LoginWithMfa", "Account", new { rememberMe = loginViewModel.RememberLogin, returnUrl = loginViewModel.ReturnUrl});
                }
                else if (signinResult.IsNotAllowed)
                {
                    var user = await _userManager.FindByNameAsync(loginViewModel.Username);
                    var emailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
                    if (!emailConfirmed)
                        ModelState.AddModelError(string.Empty, "email is not confirmed.");


                }
                ModelState.AddModelError(string.Empty, "sign in failed.");
                return View(loginViewModel);
            }
            ModelState.AddModelError(string.Empty, "invalid login attempt.");
            return View(loginViewModel);
        }

        [HttpGet]
        public async Task<IActionResult> Consent(string returnUrl)
        {
            var request = await _interaction.GetAuthorizationContextAsync(returnUrl);
            
            var consentViewModel = new ConsentViewModel();
            
            consentViewModel.ClientName = request.Client.ClientName;
            consentViewModel.ReturnUrl = returnUrl;
            
            var identityResouces = request.ValidatedResources.Resources.IdentityResources;
            var apiScopes = request.ValidatedResources.Resources.ApiScopes;
            IList<ScopeViewModel> scopes = new List<ScopeViewModel>();
            foreach(var identityResouce in identityResouces)
            {
                var scope = new ScopeViewModel()
                {
                    ScopeName = identityResouce.Name,
                    DisplayName = identityResouce.DisplayName,
                    Discription = identityResouce.Description
                };
                scopes.Add(scope);
            }
            foreach (var apiScope in apiScopes)
            {
                var scope = new ScopeViewModel()
                {
                    ScopeName = apiScope.Name,
                    DisplayName = apiScope.DisplayName,
                    Discription = apiScope.Description
                };
                scopes.Add(scope);
            }
            if (request.ValidatedResources.ParsedScopes.Where(c => c.ParsedName == "offline_access").Count() > 0)
            {
                var scope = new ScopeViewModel()
                {
                    ScopeName = "offline_access",
                    DisplayName = "Offline Access",
                    Discription = "Allow to issue refresh token."
                };
                scopes.Add(scope);

            }

            consentViewModel.Scopes = scopes;

            return View(consentViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> Consent(ConsentViewModel consentViewModel)
        {
            if (ModelState.IsValid)
            {
                ConsentResponse consentResponse = null;
                var request = await _interaction.GetAuthorizationContextAsync(consentViewModel.ReturnUrl);
                if (consentViewModel.Consented == "yes")
                {
                    var consentedScopes = new List<string>();
                    if(consentViewModel.ConsentedScopes.Count() > 0)
                    {
                        foreach (var scope in consentViewModel.ConsentedScopes)
                        {
                            consentedScopes.Add(scope);
                        }
                    }
                    consentResponse = new ConsentResponse { ScopesValuesConsented = consentedScopes, RememberConsent = true };
                }
                else
                {
                    consentResponse = new ConsentResponse { Error = AuthorizationError.AccessDenied };

                }
                await _interaction.GrantConsentAsync(request, consentResponse);
                return Redirect(consentViewModel.ReturnUrl);
            }
            return View(consentViewModel);

        }

        [HttpGet]
        public IActionResult ExternalChallenge(string provider, string returnUrl)
        {
            if (string.IsNullOrEmpty(returnUrl))
            {
                returnUrl = "/Home/Index";
            }

            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, "/Account/ExternalLogin");
            properties.Items.Add("returnUrl", returnUrl);
            return new ChallengeResult(provider, properties);
        }

        [HttpGet]
        [Authorize(AuthenticationSchemes = "Identity.External")]
        public async Task<IActionResult> ExternalLogin(string remoteError = null)
        {

            if (remoteError != null)
            {
                return RedirectToAction("Error", "Home");

            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction("Error", "Home");

            }
            var returnUrl = info.AuthenticationProperties.Items["returnUrl"] ?? Url.Content("~/Home/Index");

            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
                var claims = await _userManager.GetClaimsAsync(user);
                var exsistingsid = claims.Where(c => c.Type == "sid").FirstOrDefault();
                var newsid = info.Principal.Claims.Where(c => c.Type == "sid").FirstOrDefault();
                await _userManager.RemoveClaimAsync(user, exsistingsid);
                await _userManager.AddClaimAsync(user, newsid);
                await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

                return Redirect(returnUrl);
            }
            if (result.IsLockedOut)
            {
                return RedirectToAction("Error", "Home");
            }
            else
            {
                // need to create user, so show the user creation page.
                var externalLoginModel = new ExternalLoginModel();
                externalLoginModel.LoginProvider = info.LoginProvider;
                externalLoginModel.Claims = info.Principal.Claims;
                if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Email))
                {
                    var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                    externalLoginModel.Email = email;

                    var exsistApplicationUser = await _userManager.FindByNameAsync(email);
                    if (exsistApplicationUser != null)
                    {
                        var addProviderResult = await _userManager.AddLoginAsync(exsistApplicationUser, info);
                        if (addProviderResult.Succeeded)
                        {
                            await _signInManager.SignInAsync(exsistApplicationUser, isPersistent: false);
                            return Redirect(returnUrl);
                        }
                    }
                }
                return View(externalLoginModel);
            }
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(AuthenticationSchemes = "Identity.External")]

        public async Task<IActionResult> ExternalLogin(ExternalLoginModel externalLoginModel)
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();
            externalLoginModel.LoginProvider = info.LoginProvider;
            externalLoginModel.Claims = info.Principal.Claims;

            if (ModelState.IsValid)
            {

                var applicationUser = new ApplicationUser { UserName = externalLoginModel.Email, Email = externalLoginModel.Email, EmailConfirmed = true };
                var result = await _userManager.CreateAsync(applicationUser);
                if (result.Succeeded)
                {
                    await _userManager.AddClaimsAsync(applicationUser, info.Principal.Claims);

                    result = await _userManager.AddLoginAsync(applicationUser, info);
                    if (result.Succeeded)
                    {
                        var returnUrl = info.AuthenticationProperties.Items["returnUrl"] ?? Url.Content("/Home/Index");
                        await _signInManager.SignInAsync(applicationUser, isPersistent: false);
                        return Redirect(returnUrl);
                    }
                }
                var erros = result.Errors.ToList();
                var message = new StringBuilder();
                foreach (var error in erros)
                {
                    message.Append(error.Code + ": " + error.Description + Environment.NewLine);
                }
                ModelState.AddModelError(string.Empty, message.ToString());
                return View(externalLoginModel);

            }
            return View(externalLoginModel);
        }

        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            if (User?.Identity.IsAuthenticated == true)
            {
                var logoutViewModel = new LogoutViewModel { LogoutId = logoutId };
                return View(logoutViewModel);
            }

            if (!string.IsNullOrEmpty(logoutId))
            {
                var context = await _interaction.GetLogoutContextAsync(logoutId);
                var returnUrl = context.PostLogoutRedirectUri;
                return Redirect(returnUrl);
            }

            return RedirectToAction("Login", "Account");

        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutViewModel logoutViewModel)
        {
            
            if(ModelState.IsValid && logoutViewModel.Confirmation)
            {
                var userName = User.Identity.Name;
                await _signInManager.SignOutAsync();

                var logoutId = logoutViewModel.LogoutId;
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;

                // Logout Request from clients using endsession.
                if (!string.IsNullOrEmpty(logoutId))
                {
                    var context = await _interaction.GetLogoutContextAsync(logoutId);
                    var returnUrl = context.PostLogoutRedirectUri;
                    var frontchlogoutUri = _configurationDbContext.Clients.Where(c => c.ClientId == context.ClientId).FirstOrDefault().FrontChannelLogoutUri;

                    if (string.IsNullOrEmpty(returnUrl))
                        return Redirect(frontchlogoutUri);


                    if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                    {
                        // logout from idp.
                        var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                        if (providerSupportsSignout)
                        {
                            string url = Url.Action("Logout", new { logoutId = logoutViewModel.LogoutId });
                            return SignOut(new AuthenticationProperties { RedirectUri = url }, idp);
                        }

                    }

                    return Redirect(returnUrl);

                }

                // Logout Request from this sts not using endsession.
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                       string url = Url.Action("Logout", new { logoutId = logoutViewModel.LogoutId });
                       return SignOut(new AuthenticationProperties { RedirectUri = url }, idp);
                    }

                }

                return RedirectToAction("Login", "Account");

                //TempData["UserName"] = userName;
                //return RedirectToAction("Logout", "Saml2");
            }
            return View(logoutViewModel);
        }
        
        [HttpGet]
        public async Task<IActionResult> FrontChannelLogout(string sid)
        {
            var loginsid = User.Claims.Where(c => c.Type == "sid").FirstOrDefault().Value;

            if (sid == loginsid)
            {
                await _signInManager.SignOutAsync();
                return Ok();
            }


            return NoContent();
        }


        [HttpGet]
        public IActionResult Register(string returnUrl = null)
        {
            var regiterViewModel = new RegisterViewModel() { ReturnUrl = returnUrl};
            return View(regiterViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel registerViewModel)
        {
            if (ModelState.IsValid)
            {

                var scimGetResult = await CommonFunctions.GetScimUserAync(_configuration, registerViewModel.Username);
                if (!(bool)scimGetResult["success"])
                {

                    //not exist scimuser, first create local user
                    var applicationUser = new ApplicationUser { UserName = registerViewModel.Username, Email = registerViewModel.Username, EmailConfirmed = false };
                    var result = await _userManager.CreateAsync(applicationUser, registerViewModel.Password);

                    if (result.Succeeded)
                    {
                        // next create scim user
                        var user = await _userManager.FindByNameAsync(registerViewModel.Username);
                        var jCreatedResponse = await CommonFunctions.ProvisionScimUserAync(_configuration, user.Id, user.UserName);

                        if ((bool)jCreatedResponse["success"])
                        {
                            await AddImmutableId(user, jCreatedResponse);

                            // verify email address
                            var emailConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                            var emailConfirmationLink = Url.Action("EmailConfirmation", "Account", new { userid = user.Id, token = emailConfirmationToken }, protocol: Request.Scheme);
                            SendVerifyCode(user.UserName, emailConfirmationLink);
                            return RedirectToAction("EmailConfirmation", "Account");
                        }

                    }
                    else
                    {
                        var erros = result.Errors.ToList();
                        var message = new StringBuilder();
                        foreach (var error in erros)
                        {
                            message.Append(error.Code + ": " + error.Description + Environment.NewLine);
                        }
                        ModelState.AddModelError(string.Empty, message.ToString());
                        return View(registerViewModel);

                    }

                }
                else
                {
                    // already existing scim user then create application user

                    //crate local user
                    var applicationUser = new ApplicationUser { Id = (string)scimGetResult["Resources"][0]["id"], UserName = registerViewModel.Username, Email = registerViewModel.Username, EmailConfirmed = false };
                    var result = await _userManager.CreateAsync(applicationUser, registerViewModel.Password);

                    if (result.Succeeded)
                    {
                        var user = await _userManager.FindByNameAsync(registerViewModel.Username);

                        await AddImmutableId(user, (JObject)scimGetResult["Resources"][0]);


                        return RedirectToAction("Login", "Account", new { ReturnUrl = registerViewModel.ReturnUrl });
                    }
                    else
                    {
                        var erros = result.Errors.ToList();
                        var message = new StringBuilder();
                        foreach (var error in erros)
                        {
                            message.Append(error.Code + ": " + error.Description + Environment.NewLine);
                        }
                        ModelState.AddModelError(string.Empty, message.ToString());
                        return View(registerViewModel);
                    }

                }
                  

            }
            return View(registerViewModel);
        }
        

        [HttpGet]
        public async Task<IActionResult> EmailConfirmation(string userid, string token)
        {
            if(!string.IsNullOrEmpty(userid) && !string.IsNullOrEmpty(token))
            {
                var user = await _userManager.FindByIdAsync(userid);
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    ViewData["Message"] = "Your email address was confirmed.";
                    return View();
                }

            }
            ViewData["Message"] = "Please confirm your email address at first.";
            return View();


        }

        [HttpGet]
        public async Task<IActionResult> LoginWithMfa(bool rememberMe, string returnUrl = "/Home/Index")
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if(user == null)
            {
                throw new InvalidOperationException("Unable to load two-factor authentication.");
            }
            var loginWithMfaViewModel = new LoginWithMfaViewModel() { RememberMe = rememberMe, ReturnUrl = returnUrl };
            return View(loginWithMfaViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> LoginWithMfa(LoginWithMfaViewModel loginWithMfaViewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
                if (user == null)
                {
                    throw new InvalidOperationException("Invalid operation.");
                }
                var authenticationCode = loginWithMfaViewModel.AuthenticationCode.Replace(" ", string.Empty).Replace("-", string.Empty);
                var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticationCode, loginWithMfaViewModel.RememberMe, loginWithMfaViewModel.RememberComputer);
                if (result.Succeeded)
                {
                    return Redirect(loginWithMfaViewModel.ReturnUrl);
                }
            }
            ModelState.AddModelError(string.Empty, "invalid information");
            return View(loginWithMfaViewModel);
        }


        [HttpPost]
        [Route("/assertionOptions")]
        public async Task<IActionResult> MakeAssertionOptions([FromForm] string username, [FromForm] string userVerification)
        {
            try
            {

                var authenticationExtensionsClientInputs = new AuthenticationExtensionsClientInputs
                {
                    SimpleTransactionAuthorization = "FIDO",
                    GenericTransactionAuthorization = new TxAuthGenericArg
                    {
                        ContentType = "text/plain",
                        Content = new byte[] { 0x46, 0x49, 0x44, 0x4f },
                    },
                    UserVerificationIndex = true,
                    Location = true,
                    UserVerificationMethod = true
                };
                var userVerificationRequirement = string.IsNullOrEmpty(userVerification) ? UserVerificationRequirement.Discouraged : userVerification.ToEnum<UserVerificationRequirement>();

                /* For the use of MFA or to force authenticator to sign in with specific user.
                 * If you want to select which user sign in on authenticator, then omit those codes.

                var options = _fido2.GetAssertionOptions(existingCredentials, userVerificationRequirement, authenticationExtensionsClientInputs);

                 */
                var options = _fido2.GetAssertionOptions(null, userVerificationRequirement, authenticationExtensionsClientInputs);

                if(options.Status != "ok")
                {
                    throw new Exception("Failed to create assertion options.");
                }

                var uniqueId = Guid.NewGuid().ToString();
                UniqueId = uniqueId;
                await _distributedCache.SetStringAsync(uniqueId, options.ToJson());

                return Json(options);

            }
            catch (Exception exception)
            {
                return Json(new AssertionOptions { Status = "error", ErrorMessage = CommonFunctions.FormatException(exception) });
            }
        }


        [HttpPost]
        [Route("/makeAssertion")]
        public async Task<JsonResult> MakeAssertion([FromBody] AuthenticatorAssertionRawResponse authenticatorAssertionRawResponse)
        {
            try
            {
                var jsonOptions = await _distributedCache.GetStringAsync(UniqueId);
                if (string.IsNullOrEmpty(jsonOptions))
                {
                    throw new Exception("Cant get Credential options from cache.");
                }
                var assertionOptions = AssertionOptions.FromJson(jsonOptions);
                var fidoStoredCredential = await _fido2Service.GetFido2StoredCredentialsByCredentialIdAsync(authenticatorAssertionRawResponse.Id);
                if (fidoStoredCredential == null)
                {
                    throw new Exception("Unkown credentials.");
                }

                IsUserHandleOwnerOfCredentialIdAsync isUserHandleOwnerOfCredentialIdAsync = async (args) =>
                {
                    var storedCreds = await _fido2Service.GetFido2StoredCredentialsByUserHandleAsync(args.UserHandle);

                    var storedCredExsist = storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
                    return storedCredExsist;
                };

                var response = await _fido2.MakeAssertionAsync(authenticatorAssertionRawResponse, assertionOptions, fidoStoredCredential.PublicKey, fidoStoredCredential.SignatureCounter, isUserHandleOwnerOfCredentialIdAsync);
                if (response.Status != "ok")
                {
                    throw new Exception("Failed to assertion.");
                }

                await _fido2Service.UpdateFido2StoredCredentialCounter(response.CredentialId, response.Counter);

                var identityUser = _applicationDbContext.Users.Where(c => c.UserName == fidoStoredCredential.UserName).FirstOrDefault();
                if (identityUser == null)
                {
                    throw new Exception($"Unable to load two factor authentication user.");
                }
                await _signInManager.SignInAsync(identityUser, true);

                return Json(response);

            }
            catch (Exception exception)
            {
                return Json(new AssertionVerificationResult { Status = "error", ErrorMessage = CommonFunctions.FormatException(exception) });
            }
        }

        private async Task<bool> AddImmutableId(ApplicationUser applicationUser, JObject jObject)
        {
            var id = (string)jObject["id"];
            var claimImmutableId = new Claim("immutableId", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(id.Replace("-", ""))));
            await _userManager.AddClaimAsync(applicationUser, claimImmutableId);

            var claimScimId = new Claim("scim_id", (string)jObject["id"]);
            await _userManager.AddClaimAsync(applicationUser, claimScimId);
            var claimScimLocation = new Claim("scim_location", (string)jObject["meta"]["location"]);
            await _userManager.AddClaimAsync(applicationUser, claimScimLocation);

            return true;
        }

        private bool SendVerifyCode(string emailAddress, string bodyText)
        {
            var confidentialClient = ConfidentialClientApplicationBuilder
                .Create(_configuration["VerifyEmailClientId"])
                .WithTenantId(_configuration["VerifyEmailTenant"])
                .WithClientSecret(_configuration["VerifyEmailClientSecret"])
                .Build();

            GraphServiceClient graphServiceClient = new GraphServiceClient(new DelegateAuthenticationProvider(async (request) =>
            {
                var authResult = await confidentialClient.AcquireTokenForClient(new string[] { "https://graph.microsoft.com/.default" }).ExecuteAsync();
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authResult.AccessToken);
            }));

            var message = new Message
            {
                Subject = "Verify your email address.",
                Body = new ItemBody
                {
                    ContentType = BodyType.Html,
                    Content = "Please click the link to verify your email address. " + bodyText
                },
                ToRecipients = new List<Recipient>()
                {
                    new Recipient { EmailAddress = new EmailAddress { Address = emailAddress }}
                }
            };
            graphServiceClient.Users[_configuration["VerifyEmailSenderId"]].SendMail(message, true).Request().PostAsync().Wait();

            return true;
        }

    }
}