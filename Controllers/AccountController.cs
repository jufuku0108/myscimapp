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
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using System.Text;
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

        public AccountController(
            UserManager<ApplicationUser> userManager, 
            SignInManager<ApplicationUser> signInManager, 
            IIdentityServerInteractionService interaction, 
            ApplicationDbContext applicationDbContext,
            Fido2Service fido2Service,
            IDistributedCache distributedCache,
            IConfiguration configuration)
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
        }

        [HttpGet]
        public IActionResult Login(string returnUrl)
        {
            var loginViewModel = new LoginViewModel();
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
                    return RedirectToAction("Index", "AccountManage");
                }
                else if (signinResult.RequiresTwoFactor)
                {
                        return RedirectToAction("LoginWithMfa", "Account", new { rememberMe = loginViewModel.RememberLogin, returnUrl = loginViewModel.ReturnUrl});
                }
                ModelState.AddModelError(string.Empty, "sign in failed.");
                return View(loginViewModel);
            }
            ModelState.AddModelError(string.Empty, "invalid login attempt.");
            return View(loginViewModel);
        }

        [HttpGet]
        public IActionResult ExternalChallenge(string provider, string returnUrl)
        {
            if (string.IsNullOrEmpty(returnUrl))
            {
                returnUrl = "/AccountManage";
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
            var returnUrl = info.AuthenticationProperties.Items["returnUrl"] ?? Url.Content("~/AccountManage");

            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                return Redirect(returnUrl);
            }
            if (result.IsLockedOut)
            {
                return RedirectToAction("Error", "Home");
            }
            else
            {

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
                    ProvisionScimUser(applicationUser, "ExternalUser");

                    result = await _userManager.AddLoginAsync(applicationUser, info);
                    if (result.Succeeded)
                    {
                        var returnUrl = info.AuthenticationProperties.Items["returnUrl"] ?? Url.Content("/AccountManage");
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
        [AutoValidateAntiforgeryToken]
        public async Task<IActionResult> Logout(LogoutViewModel logoutViewModel)
        {
            
            if(ModelState.IsValid && logoutViewModel.Confirmation)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if(idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        await _signInManager.SignOutAsync();
                        string url = Url.Action("Logout", new { logoutId = logoutViewModel.LogoutId });
                       return SignOut(new AuthenticationProperties { RedirectUri = url }, idp);
                    }

                }
                await _signInManager.SignOutAsync();

                var logoutId = logoutViewModel.LogoutId;
                if (!string.IsNullOrEmpty(logoutId))
                {
                    var context = await _interaction.GetLogoutContextAsync(logoutId);
                    var returnUrl = context.PostLogoutRedirectUri;
                    return Redirect(returnUrl);

                }

                return RedirectToAction("Login", "Account");
            }
            return View(logoutViewModel);
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
                var applicationUser = new ApplicationUser { UserName = registerViewModel.Username, Email = registerViewModel.Username, EmailConfirmed = true, UserType = "ApplicationUser" };
                var result = await _userManager.CreateAsync(applicationUser, registerViewModel.Password);
                if (result.Succeeded)
                {
                    ProvisionScimUser(applicationUser, "ApplicationUser");
                    return RedirectToAction("Login", "Account", new { ReturnUrl = registerViewModel.ReturnUrl });
                }
                var erros = result.Errors.ToList();
                var message = new StringBuilder();
                foreach (var error in erros)
                {
                    message.Append(error.Code + ": " + error.Description + Environment.NewLine);
                }
                ModelState.AddModelError(string.Empty, message.ToString());
            }
            return View(registerViewModel);
        }
        

        [HttpGet]
        public async Task<IActionResult> LoginWithMfa(bool rememberMe, string returnUrl = "/AccountManage")
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
                /* For the use of MFA or to force authenticator to sign in with specific user.
                 * If you want to select which user sign in on authenticator, then omit those codes.
                 
                var identityUser = await _signInManager.GetTwoFactorAuthenticationUserAsync();
                if (identityUser == null)
                {
                    throw new InvalidOperationException($"Unable to load two factor authentication user.");
                }
                var existingCredentials = new List<PublicKeyCredentialDescriptor>();
                var fido2User = new Fido2User
                {
                    DisplayName = identityUser.UserName,
                    Name = identityUser.UserName,
                    Id = UTF8Encoding.UTF8.GetBytes(identityUser.UserName)
                };
                var fidoStoredCredentials = await _fido2Service.GetFido2StoredCredentialsByUserNameAsync(identityUser.UserName);
                existingCredentials = fidoStoredCredentials.Select(c => c.Descriptor).ToList();
                
                 */

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




        private void ProvisionScimUser(ApplicationUser applicationUser, string userType)
        {
            var scimUser = new ScimUser
            {
                Schemas = new string[] { "urn:ietf:params:scim:schemas:core:2.0:User" },
                UserName = applicationUser.UserName,
                Active = true,
                Roles = new string[] { },
                UserType = userType
            };
            var scimUserName = new ScimUserName();
            var scimUserPhoneNumbers = new List<ScimUserPhoneNumber>();
            var scimUserEmails = new List<ScimUserEmail>() { new ScimUserEmail { Primary = true, Type = "work", Value = applicationUser.Email } };
            var creationTime = DateTime.UtcNow;
            var varsion = CommonFunctions.GetSHA256HashedString(creationTime.ToString());
            var etag = "W/\"" + varsion + "\"";

            var scimUserMetaData = new ScimUserMetaData
            {
                ResourceType = "User",
                Created = DateTime.UtcNow,
                LastModified = DateTime.UtcNow,
                Version = etag
            };

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

            _applicationDbContext.scimUsers.Add(scimUser);
            _applicationDbContext.scimUserNames.Add(scimUserName);
            _applicationDbContext.scimUserPhoneNumbers.AddRange(scimUserPhoneNumbers);
            _applicationDbContext.scimUserEmails.AddRange(scimUserEmails);
            _applicationDbContext.scimUserMetaDatas.Add(scimUserMetaData);
            _applicationDbContext.SaveChanges();

        }

    }
}