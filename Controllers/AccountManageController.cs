using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using IdentityServer4.Endpoints.Results;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using MyScimApp.Models;
using Fido2NetLib;
using Fido2NetLib.Objects;
using MyScimApp.Extensions;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.CodeAnalysis.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;

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

        public AccountManageController(
            UserManager<ApplicationUser> userManager,
            UrlEncoder urlEncoder,
            Fido2Service fido2Service,
            IDistributedCache distributedCache,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _urlEncoder = urlEncoder;
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


        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if(user.PasswordHash != null)
            {
                ViewData["disabled"] = "";
            }
            else
            {
                ViewData["disabled"] = "disabled";
            }
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
                        ViewData["Message"] = "Your authenticator app has been verified.";

                        if(await _userManager.CountRecoveryCodesAsync(user) == 0)
                        {
                            var codes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                            var recoveryCodes = new StringBuilder();
                            foreach(var code in codes)
                            {
                                recoveryCodes.Append(code).Append(" ");
                            }
                            ViewData["RecoveryCodes"] = " In case of you lost your mobile phone, write down 10 recovery codes below. \r\n" + recoveryCodes.ToString();
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
                    return RedirectToAction("Index");
                }
            }
            ModelState.AddModelError(string.Empty, "invalid operation.");
            return View(disableMfaViewModel);
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
                return RedirectToAction("Index", "AccountManage");
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
                newFido2StoredCredential.AaGuid = Guid.NewGuid();
                newFido2StoredCredential.Descriptor = new PublicKeyCredentialDescriptor(result.Result.CredentialId);

                _fido2Service.AddFido2StoredCredential(newFido2StoredCredential);

                return Json(result);

            }
            catch (Exception exception)
            {
                return Json(new CredentialCreateOptions() { Status = "error", ErrorMessage = CommonFunctions.FormatException(exception) });
            }

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