using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using MyScimApp.Extensions;
using Microsoft.EntityFrameworkCore;
using MyScimApp.Models;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using IdentityServer4.Models;
using MyScimApp.Data.Users;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;

namespace MyScimApp.Controllers
{
    [Authorize]
    public class AccountManageController : Controller
    {
        [TempData]
        public string UniqueId { get; set; }
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly UrlEncoder _urlEncoder;
        private readonly Fido2Service _fido2Service;
        private readonly IDistributedCache _distributedCache;
        private readonly Fido2 _fido2;
        private IConfiguration _configuration;
        private ConfigurationDbContext _configurationDbContext;
        private readonly ApplicationDbContext _applicationDbContext;

        public AccountManageController(
            UserManager<ApplicationUser> userManager,
            UrlEncoder urlEncoder,
            Fido2Service fido2Service,
            IDistributedCache distributedCache,
            IConfiguration configuration,
            ConfigurationDbContext configurationDbContext,
            ApplicationDbContext applicationDbContext)
        {
            _userManager = userManager;
            _urlEncoder = urlEncoder;
            _fido2Service = fido2Service;
            _distributedCache = distributedCache;
            _configuration = configuration;
            _configurationDbContext = configurationDbContext;
            _applicationDbContext = applicationDbContext;

            _fido2 = new Fido2(new Fido2Configuration()
            {
                ServerDomain = _configuration["Fido2ServerDomain"],
                ServerName = "MyScimApp",
                Origin = "https://" + _configuration["Fido2ServerDomain"]
            });
        }


        public IActionResult MyProfile()
        {
            TempData["myprofile"] = "active";
            return View();
        }

        [HttpGet]
        public IActionResult MultiFactorAuth()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> EnableMfa()
        {
            var user = await _userManager.GetUserAsync(User);
            if(user.PasswordHash == null)
            {
                return RedirectToAction("Index", "AccountManage");
            }
            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            var sharedKey = unformattedKey.ToLowerInvariant();

            var email = await _userManager.GetEmailAsync(user);
            var qrCodeUri = GenerateQrCodeUri(email, unformattedKey);

            var accountMfaInformation = new AccountMfaInformation { SharedKey = sharedKey, QrlCodeUri = qrCodeUri };
            return View(accountMfaInformation);
        }

        [HttpPost]
        public async Task<IActionResult> EnableMfa(AccountMfaInformation accountMfaInformation)
        {
            if (ModelState.IsValid)
            {
                if (!string.IsNullOrEmpty(accountMfaInformation.VerifyCode))
                {
                    var verifyCode = accountMfaInformation.VerifyCode.Replace(" ", string.Empty).Replace("-", string.Empty);

                    var authenticatorProvider = _userManager.Options.Tokens.AuthenticatorTokenProvider;
                    var user = await _userManager.GetUserAsync(User);
                    var isVerifyCodeValid = await _userManager.VerifyTwoFactorTokenAsync(user, authenticatorProvider, verifyCode);

                    if (isVerifyCodeValid)
                    {
                        await _userManager.SetTwoFactorEnabledAsync(user, true);
                        ViewData["Message"] = "Your authenticator app has been verified. In case of you lost your mobile phone, write down 10 recovery codes below. \r\n";

                        if(await _userManager.CountRecoveryCodesAsync(user) == 0)
                        {
                            var codes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                            var recoveryCodes = new StringBuilder();
                            foreach(var code in codes)
                            {
                                recoveryCodes.Append(code).Append(" ");
                            }
                            ViewData["RecoveryCodes"] = recoveryCodes.ToString();
                            return View(accountMfaInformation);
                        }
                        return View(accountMfaInformation);

                    }
                }
                ModelState.AddModelError(string.Empty, "invalid verify code.");
                return View(accountMfaInformation);
            }
            ModelState.AddModelError(string.Empty, "invalid mfa registration.");
            return View(accountMfaInformation);
        }

        [HttpGet]
        public IActionResult DisableMfa()
        {
            var disableMfaViewModel = new DisableMfaViewModel();
            return View(disableMfaViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> DisableMfa(DisableMfaViewModel disableMfaViewModel)
        {
            if (ModelState.IsValid)
            {
                if (disableMfaViewModel.Confirmation)
                {
                    var user = await _userManager.GetUserAsync(User);
                    if (user == null)
                    {
                        throw new InvalidOperationException();
                    }
                    var result = await _userManager.SetTwoFactorEnabledAsync(user, false);
                    return RedirectToAction("MyProfile");
                }
            }
            ModelState.AddModelError(string.Empty, "invalid operation.");
            return View(disableMfaViewModel);
        }

        [HttpGet]
        public IActionResult Fido2()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> EnableFido2()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user.PasswordHash == null)
            {
                return RedirectToAction("Index", "AccountManage");
            }
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> DisableFido2()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user.PasswordHash == null)
            {
                return RedirectToAction("Index", "AccountManage");
            }
            var disableFido2ViewModel = new DisableFido2ViewModel { };
            return View(disableFido2ViewModel);
        }
        
        [HttpPost]
        public async Task<IActionResult> DisableFido2(DisableFido2ViewModel disableFido2ViewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                {
                    return new NotFoundResult();
                }
                if (disableFido2ViewModel.Confirmation)
                    _fido2Service.RemoveFido2StoredCredentialsByUserNameAsync(user.UserName);
                return RedirectToAction("MyProfile", "AccountManage");
            }
            ModelState.AddModelError(string.Empty, "invalid operation.");
            return View(disableFido2ViewModel);
        }

        [HttpPost]
        [Route("/makeCredentialOptions")]
        public async Task<JsonResult> MakeCredentialOptions(
            [FromForm] string attType,
            [FromForm] string authType,
            [FromForm] bool requireResidentKey,
            [FromForm] string userVerification)
        {
            try
            {
                var identityUser = await _userManager.GetUserAsync(User);
                if(identityUser == null)
                {
                    throw new Exception("Unable to retrieve user.");
                }

                var fido2User = new Fido2User
                {
                    DisplayName = identityUser.UserName,
                    Name = identityUser.UserName,
                    Id = UTF8Encoding.UTF8.GetBytes(identityUser.UserName)
                };

                var fido2StoredCredentials = await _fido2Service.GetFido2StoredCredentialsByUserNameAsync(identityUser.UserName);

                var existingKeys = new List<PublicKeyCredentialDescriptor>();
                foreach (var fido2StoredCredential in fido2StoredCredentials)
                {
                    existingKeys.Add(fido2StoredCredential.Descriptor);
                }
                var authenticatorSelections = new AuthenticatorSelection
                {
                    RequireResidentKey = requireResidentKey,
                    UserVerification = userVerification.ToEnum<UserVerificationRequirement>()
                };
                if (!string.IsNullOrEmpty(authType))
                {
                    authenticatorSelections.AuthenticatorAttachment = authType.ToEnum<AuthenticatorAttachment>();
                }
                var exts = new AuthenticationExtensionsClientInputs()
                {
                    Extensions = true,
                    UserVerificationIndex = true,
                    Location = true,
                    UserVerificationMethod = true,
                    BiometricAuthenticatorPerformanceBounds = new AuthenticatorBiometricPerfBounds { FAR = float.MaxValue, FRR = float.MaxValue }
                };
                var options = _fido2.RequestNewCredential(fido2User, existingKeys, authenticatorSelections, attType.ToEnum<AttestationConveyancePreference>(), exts);

                if(options.Status != "ok")
                {
                    throw new Exception("Failed to create options.");
                }

                var uniqueId = Guid.NewGuid().ToString();
                UniqueId = uniqueId;

                await _distributedCache.SetStringAsync(uniqueId, options.ToJson());
                return Json(options);

            }
            catch (Exception exception)
            {
                return Json(new CredentialCreateOptions() { Status = "error", ErrorMessage = CommonFunctions.FormatException(exception) });
            }
        }

        [HttpPost]
        [Route("/makeCredential")]
        public async Task<JsonResult> MakeCredential([FromBody] AuthenticatorAttestationRawResponse authenticatorAttestationRawResponse)
        {
            try
            {
                var user = await _userManager.GetUserAsync(User);
                if(user == null)
                {
                    throw new Exception("Unable to retrieve user.");
                }

                var jsonOptions = await _distributedCache.GetStringAsync(UniqueId);
                if (string.IsNullOrEmpty(jsonOptions))
                {
                    throw new Exception("Cant get Credential options from cache.");
                }
                var options = CredentialCreateOptions.FromJson(jsonOptions);

                IsCredentialIdUniqueToUserAsyncDelegate isCredentialIdUniqueToUserAsyncDelegate = async (IsCredentialIdUniqueToUserParams isCredentialIdUniqueToUserParams) =>
                {
                    var fido2Users = await _fido2Service.GetFido2UsersByCredentialIdAsync(isCredentialIdUniqueToUserParams.CredentialId);
                    if (fido2Users.Count > 0)
                    {
                        return false;
                    }
                    return true;
                };
                var result = await _fido2.MakeNewCredentialAsync(authenticatorAttestationRawResponse, options, isCredentialIdUniqueToUserAsyncDelegate);

                if (result.Status != "ok")
                {
                    throw new Exception("Unable to create credential.");
                }


                var newFido2StoredCredential = new Fido2StoredCredential { };
                newFido2StoredCredential.UserName = options.User.Name;
                newFido2StoredCredential.UserId = options.User.Id;
                newFido2StoredCredential.PublicKey = result.Result.PublicKey;
                newFido2StoredCredential.UserHandle = result.Result.User.Id;
                newFido2StoredCredential.SignatureCounter = result.Result.Counter;
                newFido2StoredCredential.CredType = result.Result.CredType;
                newFido2StoredCredential.RegDate = DateTime.Now;
                newFido2StoredCredential.AaGuid = result.Result.Aaguid;
                newFido2StoredCredential.Descriptor = new PublicKeyCredentialDescriptor(result.Result.CredentialId);

                _fido2Service.AddFido2StoredCredential(newFido2StoredCredential);

                return Json(result);

            }
            catch (Exception exception)
            {
                return Json(new CredentialCreateOptions() { Status = "error", ErrorMessage = CommonFunctions.FormatException(exception) });
            }

        }

        [HttpGet]
        public IActionResult MyRelyingParties()
        {
            var applications = _configurationDbContext.Clients.AsQueryable().Where(c => c.Description == User.Identity.Name)
                .Include(c => c.RedirectUris)
                .ToList();

            return View(applications);
        }

        [HttpGet]
        public IActionResult RegisterMyRelyingParty()
        {
            var myApplication = new RegisterClientModel();
            return View(myApplication);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult RegisterMyRelyingParty(RegisterClientModel registerClientModel)
        {
            if (ModelState.IsValid)
            {

                switch (registerClientModel.GrantType)
                {
                    case "Code/WebApplication":
                        var webapplication = new Client
                        {
                            Description = User.Identity.Name,
                            ClientId = Guid.NewGuid().ToString(),
                            AllowedGrantTypes = GrantTypes.Code,
                            RequireConsent = true,
                            AlwaysIncludeUserClaimsInIdToken = true,
                            RequirePkce = false,
                            AccessTokenLifetime = registerClientModel.AccessTokenLifetimeSeconds

                        };
                        if(registerClientModel.ClientName != null)
                            webapplication.ClientName = registerClientModel.ClientName;

                        if(registerClientModel.ClientSecret != null)
                            webapplication.ClientSecrets =  new[]{ new Secret(registerClientModel.ClientSecret.Sha256())};

                        if(registerClientModel.Scope?.Count() > 0)
                        {
                            webapplication.AllowedScopes = registerClientModel.Scope;
                            if (registerClientModel.Scope.Contains("offline_access"))
                            {
                                webapplication.AllowOfflineAccess = true;
                            }
                        }

                        if(registerClientModel.RedirectUris?.Count() > 0)
                        {
                            string[] webrdctUrls = registerClientModel.RedirectUris.Split(",");
                            webapplication.RedirectUris = webrdctUrls;
                        }
                        if (registerClientModel.PostLogoutRedirectUris?.Count() > 0)
                        {
                            string[] webpstlgtUrls = registerClientModel.PostLogoutRedirectUris?.Split(",");
                            webapplication.PostLogoutRedirectUris = webpstlgtUrls;
                        }
                        if (registerClientModel.BackChannelLogoutUri != null)
                            webapplication.BackChannelLogoutUri = registerClientModel.BackChannelLogoutUri;
                        if (registerClientModel.FrontChannelLogoutUri != null)
                            webapplication.FrontChannelLogoutUri = registerClientModel.FrontChannelLogoutUri;


                        _configurationDbContext.Clients.Add(webapplication.ToEntity());
                        _configurationDbContext.SaveChanges();
                        break;

                    case "Code/SinglePageApplication":
                        string[] spardctUrls = registerClientModel.RedirectUris.Split(",");
                        string[] spaoriginorg = spardctUrls[0].Split('/');
                        string spaorigin = "https://" + spaoriginorg[2];
                        string[] spapstlgtUrls = registerClientModel.PostLogoutRedirectUris.Split(",");
                        var codeapplication = new Client
                        {
                            Description = User.Identity.Name,
                            ClientId = Guid.NewGuid().ToString(),
                            ClientName = registerClientModel.ClientName,
                            AllowedGrantTypes = GrantTypes.Code,
                            AllowedScopes = registerClientModel.Scope,
                            RedirectUris = spardctUrls,
                            PostLogoutRedirectUris = spapstlgtUrls,
                            BackChannelLogoutUri = registerClientModel.BackChannelLogoutUri,
                            RequireConsent = false,
                            RequirePkce = true,
                            RequireClientSecret = false,
                            AllowAccessTokensViaBrowser = true,
                            AllowedCorsOrigins = { spaorigin },
                            AccessTokenLifetime = registerClientModel.AccessTokenLifetimeSeconds


                        };
                        _configurationDbContext.Clients.Add(codeapplication.ToEntity());
                        _configurationDbContext.SaveChanges();

                        break;
                    case "ClientCredentials/DemonApplication":
                        var demonapplication = new Client
                        {
                            Description = User.Identity.Name,
                            ClientId = Guid.NewGuid().ToString(),
                            ClientName = registerClientModel.ClientName,
                            ClientSecrets = { new Secret(registerClientModel.ClientSecret.Sha256()) },
                            AllowedGrantTypes = GrantTypes.ClientCredentials,
                            AllowedScopes = registerClientModel.Scope,
                            RequireConsent = false,
                            AccessTokenLifetime = registerClientModel.AccessTokenLifetimeSeconds

                        };
                        _configurationDbContext.Clients.Add(demonapplication.ToEntity());
                        _configurationDbContext.SaveChanges();
                        
                        break;

                    case "ResourceOwnerPasswordCredentials":
                        var ropcClient = new Client
                        {
                            Description = User.Identity.Name,
                            ClientId = Guid.NewGuid().ToString(),
                            AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
                            RequireConsent = true,
                            AlwaysIncludeUserClaimsInIdToken = true,
                            RequirePkce = false,
                            AccessTokenLifetime = registerClientModel.AccessTokenLifetimeSeconds

                        };
                        if (registerClientModel.ClientName != null)
                            ropcClient.ClientName = registerClientModel.ClientName;

                        if (registerClientModel.ClientSecret != null)
                            ropcClient.ClientSecrets = new[] { new Secret(registerClientModel.ClientSecret.Sha256()) };


                        if (registerClientModel.Scope?.Count() > 0)
                        {
                            ropcClient.AllowedScopes = registerClientModel.Scope;
                            if (registerClientModel.Scope.Contains("offline_access"))
                            {
                                ropcClient.AllowOfflineAccess = true;
                            }
                        }

                        _configurationDbContext.Clients.Add(ropcClient.ToEntity());
                        _configurationDbContext.SaveChanges();
                        break;



                }
                return RedirectToAction("MyRelyingParties", "AccountManage");

            }
            return View(registerClientModel);
        }

        public IActionResult DeleteMyRelyingParty(int id)
        {
            var application = _configurationDbContext.Clients.AsQueryable().Where(c => c.Id == id).FirstOrDefault();
            _configurationDbContext.Clients.Remove(application);
            _configurationDbContext.SaveChanges();
            return RedirectToAction("MyRelyingParties", "AccountManage");

        }

        [HttpGet]
        public IActionResult MySaml2Partners()
        {
            var mySaml2ServiceProviders = _applicationDbContext.Saml2Partners.Where(c => c.RegisteredBy == User.Identity.Name);

            return View(mySaml2ServiceProviders);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult RegisterMySaml2Partner(Saml2Partner saml2Partner)
        {
            if (ModelState.IsValid)
            {


                var entityDescriptor = new EntityDescriptor();
                entityDescriptor.ReadSPSsoDescriptorFromUrl(new Uri(saml2Partner.MetadataUrl));
                saml2Partner.Issuer = entityDescriptor.EntityId;
                saml2Partner.RegisteredBy = User.Identity.Name;

                _applicationDbContext.Saml2Partners.Add(saml2Partner);
                _applicationDbContext.SaveChanges();
                return RedirectToAction("MySaml2Partners", "AccountManage");


            }
            return View(saml2Partner);
        }

        public IActionResult DeleteMySaml2Partner(int id)
        {
            var saml2Partner = _applicationDbContext.Saml2Partners.Where(c => c.Saml2PartnerId == id).FirstOrDefault();
            _applicationDbContext.Saml2Partners.Remove(saml2Partner);
            _applicationDbContext.SaveChanges();
            return RedirectToAction("MySaml2Partners", "AccountManage");

        }



        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            return string.Format(
                "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6",
                _urlEncoder.Encode("MyScimApp"),
                _urlEncoder.Encode(email),
                unformattedKey);
        }
    }
}