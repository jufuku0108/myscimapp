using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Util;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using MyScimApp.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;
using MyScimApp.Extensions;
using System.Security.Claims;
//using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.AspNetCore.Authentication;
using MyScimApp.Data.Users;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using System.ServiceModel.Security;
using System.Diagnostics;

namespace MyScimApp.Controllers
{
    public class Saml2Controller : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ApplicationDbContext _applicationDbContext;

        public Saml2Controller(
            IConfiguration configuration,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ApplicationDbContext applicationDbContext)
        {
            _configuration = configuration;
            _userManager = userManager;
            _signInManager = signInManager;
            _applicationDbContext = applicationDbContext;

        }

        [HttpGet]
        public IActionResult SpLogin()
        {
            // authenticate sp mode
            var saml2ConfigurationViewModel = new Saml2ConfigurationViewModel();
            saml2ConfigurationViewModel.EntityId = _configuration["Saml2EntityId"];
            return View(saml2ConfigurationViewModel);

        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult SpLogin(Saml2ConfigurationViewModel saml2ConfigurationViewModel)
        {
            // load Idp info
            var saml2Configuration = new Saml2Configuration() 
            {
                CertificateValidationMode = X509CertificateValidationMode.None,
                RevocationMode = X509RevocationMode.NoCheck
            };
            //saml2Configuration.AllowedAudienceUris.Add(saml2ConfigurationViewModel.Issuer);

            //TempData["IdPMetadataUrl"] = saml2ConfigurationViewModel.IdPMetadataUrl;
            var entityDescriptor = new EntityDescriptor();
            entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(saml2ConfigurationViewModel.IdPMetadataUrl));

            if (entityDescriptor.IdPSsoDescriptor != null)
            {
                saml2Configuration.AllowedIssuer = entityDescriptor.EntityId;
                saml2Configuration.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                saml2Configuration.SingleLogoutDestination = entityDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location;
                saml2Configuration.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
                if (entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.HasValue)
                    saml2Configuration.SignAuthnRequest = entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.Value;
            }
            var nameIdPolicy = new NameIdPolicy();
            nameIdPolicy.AllowCreate = true;
            switch (saml2ConfigurationViewModel.NameIdFormat)
            {
                case "EmailAddress":
                    nameIdPolicy.Format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
                    break;
                case "X509SubjectName":
                    nameIdPolicy.Format = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
                    break;
                case "WindowsDomainQualifiedName":
                    nameIdPolicy.Format = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";
                    break;
                case "Kerberos":
                    nameIdPolicy.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";
                    break;
                case "Persistent":
                    nameIdPolicy.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
                    break;
                case "Transient":
                    nameIdPolicy.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
                    break;
                case "Encrypted":
                    nameIdPolicy.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted";
                    break;
                case "Unspecified":
                    nameIdPolicy.Format = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
                    break;
            }





            if (saml2ConfigurationViewModel.BindingMode == "Redirect")
            {
                // crate and response saml request redirect binding.
                var binding = new Saml2RedirectBinding();
                binding.SetRelayStateQuery(new Dictionary<string, string> { { "ReturnUrl", saml2ConfigurationViewModel.ReturnUrl ?? Url.Content("~/") } });

                return binding.Bind(new Saml2AuthnRequest(saml2Configuration)
                {
                    AssertionConsumerServiceUrl = new Uri(_configuration["Saml2EntityId"] + "/saml2/assertionConsumerservice"),
                    Issuer = saml2ConfigurationViewModel.EntityId,
                    NameIdPolicy = nameIdPolicy
                }).ToActionResult();

            }
            else
            {
                var binding = new Saml2PostBinding();
                binding.SetRelayStateQuery(new Dictionary<string, string> { { "ReturnUrl", saml2ConfigurationViewModel.ReturnUrl ?? Url.Content("~/") } });
                return binding.Bind(new Saml2AuthnRequest(saml2Configuration)
                {
                    AssertionConsumerServiceUrl = new Uri(_configuration["Saml2EntityId"] + "/saml2/assertionConsumerservice"),
                    Issuer = saml2ConfigurationViewModel.EntityId,
                    NameIdPolicy = nameIdPolicy
                }).ToActionResult();

            }
        }

        public async Task<IActionResult> AssertionConsumerService()
        {
            // read saml response
            var saml2Configuration = new Saml2Configuration() 
            {
                CertificateValidationMode = X509CertificateValidationMode.None,
                RevocationMode = X509RevocationMode.NoCheck
            };
            var saml2AuthnResponse = new Saml2AuthnResponse(saml2Configuration);
            saml2Configuration.AllowedAudienceUris.Add(_configuration["Saml2EntityId"]);
            var binding = new Saml2PostBinding();
            var httpRequest = Request.ToGenericHttpRequest();
            binding.ReadSamlResponse(httpRequest, saml2AuthnResponse);


            // load Idp
            var saml2Partner = _applicationDbContext.Saml2Partners.Where(c => c.Issuer == saml2AuthnResponse.Issuer).FirstOrDefault();
            if (saml2Partner == null)
                return BadRequest();

            var entityDescriptor = new EntityDescriptor();
            entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(saml2Partner.MetadataUrl));

            if (entityDescriptor.IdPSsoDescriptor != null)
            {
                saml2Configuration.AllowedIssuer = entityDescriptor.EntityId;
                saml2Configuration.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                saml2Configuration.SingleLogoutDestination = entityDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location;
                saml2Configuration.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
                if (entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.HasValue)
                    saml2Configuration.SignAuthnRequest = entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.Value;
            }




            // validate saml response
            binding.Unbind(httpRequest, saml2AuthnResponse);


            // create auth session
            var namedId = saml2AuthnResponse.NameId.Value;

            var user = await _userManager.FindByNameAsync(namedId);
            if(user == null)
            {
                var scimUser = await CommonFunctions.GetScimUserAync(_configuration, namedId);
                if (!(bool)scimUser["success"])
                {
                    var applicationUser = new ApplicationUser { UserName = namedId, EmailConfirmed = true };
                    await _userManager.CreateAsync(applicationUser);
                    var createdUser = await _userManager.FindByNameAsync(namedId);

                    var jCreatedResponse = await CommonFunctions.ProvisionScimUserAync(_configuration, createdUser.Id, createdUser.UserName);

                    if ((bool)jCreatedResponse["success"])
                    {
                        var claimScimId = new Claim("scim_id", (string)jCreatedResponse["id"]);
                        await _userManager.AddClaimAsync(createdUser, claimScimId);
                        var claimScimLocation = new Claim("scim_location", (string)jCreatedResponse["meta"]["location"]);
                        await _userManager.AddClaimAsync(createdUser, claimScimLocation);

                        await _signInManager.SignInAsync(createdUser, false);
                    }
                }
                else
                {
                    var applicationUser = new ApplicationUser { Id = (string)scimUser["Resources"][0]["id"], UserName = namedId, Email = namedId, EmailConfirmed = true };
                    await _userManager.CreateAsync(applicationUser);

                    var createdUser = await _userManager.FindByNameAsync(namedId);

                    var claimScimId = new Claim("scim_id", (string)scimUser["Resources"][0]["id"]);
                    await _userManager.AddClaimAsync(createdUser, claimScimId);
                    var claimScimLocation = new Claim("scim_location", (string)scimUser["Resources"][0]["meta"]["location"]);
                    await _userManager.AddClaimAsync(createdUser, claimScimLocation);

                    await _signInManager.SignInAsync(createdUser, false);

                }

            }
            else
            {
                await _signInManager.SignInAsync(user, false);
            }


            // redirect original page
            TempData["SessionIndex"] = saml2AuthnResponse.SessionIndex;
            TempData["Partner"] = saml2Partner.Issuer;
            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey("ReturnUrl") ? relayStateQuery["ReturnUrl"] : Url.Content("~/");
            return Redirect(returnUrl);

        }

        public IActionResult Login()
        {
            // get http request
            var httpRequest = Request.ToGenericHttpRequest();

            // idp config 
            var saml2Configuration = new Saml2Configuration()
            {
                Issuer = _configuration["Saml2EntityId"],
                SigningCertificate = RetrieveIdpCert(),
                CertificateValidationMode = X509CertificateValidationMode.None,
                RevocationMode = X509RevocationMode.NoCheck
            };

            if (httpRequest.Method == "POST")
            {
                if (httpRequest.Form.AllKeys.Contains("SAMLRequest"))
                {
                    // authenticate as Idp mode.
                    var requestBinding = new Saml2PostBinding();

                    // read saml2 request
                    var samlAuthnRequest = new Saml2AuthnRequest(saml2Configuration);
                    requestBinding.ReadSamlRequest(httpRequest, samlAuthnRequest);


                    // validate relaying party
                    var saml2ServiceProvider = _applicationDbContext.Saml2Partners.Where(c => c.Issuer == samlAuthnRequest.Issuer).FirstOrDefault();
                    if (saml2ServiceProvider == null)
                        return BadRequest();
                    TempData["Partner"] = saml2ServiceProvider.Issuer;
                    var entityDescriptor = new EntityDescriptor();
                    entityDescriptor.ReadSPSsoDescriptorFromUrl(new Uri(saml2ServiceProvider.MetadataUrl));
                    var assertionConsumerService = entityDescriptor.SPSsoDescriptor.AssertionConsumerServices.FirstOrDefault().Location.ToString();

                    // validate
                    requestBinding.Unbind(httpRequest, samlAuthnRequest);

                    // check user authenticated
                    if (!User.Identity.IsAuthenticated)
                    {
                        var userName = httpRequest.Form.GetValues("userName");
                        SaveSaml2Info(requestBinding.RelayState.ToString(), samlAuthnRequest.Id.Value.ToString(), assertionConsumerService, saml2ServiceProvider.Issuer.ToString());
                        return RedirectToAction("Login", "Account", new { userName = userName, returnUrl = "/Saml2/Login" });
                    }


                    // retrun login response
                    var responseBinding = new Saml2PostBinding();
                    responseBinding.RelayState = requestBinding.RelayState;
                    var saml2AuthnResponse = CreateSaml2Response(saml2Configuration, samlAuthnRequest.Id.Value.ToString(), assertionConsumerService, saml2ServiceProvider.Issuer);
                    return responseBinding.Bind(saml2AuthnResponse).ToActionResult();

                }

            }
            else if (httpRequest.Method == "GET")
            {
                if (httpRequest.Query.AllKeys.Contains("SAMLRequest"))
                {
                    // authenticate as Idp mode.
                    var requestBinding = new Saml2RedirectBinding();

                    // read saml2 request
                    var samlAuthnRequest = new Saml2AuthnRequest(saml2Configuration);
                    requestBinding.ReadSamlRequest(httpRequest, samlAuthnRequest);

                    // validate relaying party 
                    var saml2ServiceProvider = _applicationDbContext.Saml2Partners.Where(c => c.Issuer == samlAuthnRequest.Issuer).FirstOrDefault();
                    if (saml2ServiceProvider == null)
                        return BadRequest();
                    TempData["Partner"] = saml2ServiceProvider.Issuer;

                    var entityDescriptor = new EntityDescriptor();
                    entityDescriptor.ReadSPSsoDescriptorFromUrl(new Uri(saml2ServiceProvider.MetadataUrl));
                    var assertionConsumerService = entityDescriptor.SPSsoDescriptor.AssertionConsumerServices.FirstOrDefault().Location.ToString();

                    // validate
                    requestBinding.Unbind(httpRequest, samlAuthnRequest);

                    // check user authenticated
                    if (!User.Identity.IsAuthenticated)
                    {
                        var userName = httpRequest.Query.GetValues("userName");

                        SaveSaml2Info(requestBinding.RelayState.ToString(), samlAuthnRequest.Id.Value.ToString(), assertionConsumerService, saml2ServiceProvider.Issuer.ToString());
                        return RedirectToAction("Login", "Account", new { userName = userName, returnUrl = "/Saml2/Login" });
                    }

                    // retrun login response
                    var responseBinding = new Saml2PostBinding();
                    responseBinding.RelayState = requestBinding.RelayState;
                    var saml2AuthnResponse = CreateSaml2Response(saml2Configuration, samlAuthnRequest.Id.Value.ToString(), assertionConsumerService, saml2ServiceProvider.Issuer);
                    return responseBinding.Bind(saml2AuthnResponse).ToActionResult();

                }
                else
                {
                    // check user is authenticated
                    if (!User.Identity.IsAuthenticated)
                        return RedirectToAction("Login", "Account", new { returnUrl = "/Saml2/Login" });
                    
                    var relayState = TempData["RelayState"].ToString();
                    var inResponseTo = TempData["InResponseTo"].ToString();
                    var destination = TempData["Destination"].ToString();
                    var issuer = TempData["Issuer"].ToString();


                    // retrun login response
                    var responseBinding = new Saml2PostBinding();
                    responseBinding.RelayState = relayState;
                    var saml2AuthnResponse = CreateSaml2Response(saml2Configuration, inResponseTo, destination, issuer);
                    return responseBinding.Bind(saml2AuthnResponse).ToActionResult();

                }

            }
            return BadRequest();

        }
        public async Task<IActionResult> Logout()
        {
            // read http object
            var httpRequest = Request.ToGenericHttpRequest();

            if (httpRequest.Method == "POST")
            {
                if (httpRequest.Form.AllKeys.Contains("SAMLRequest"))
                {
                    // read saml logout request from sp
                    var saml2Configuration = new Saml2Configuration()
                    {
                        CertificateValidationMode = X509CertificateValidationMode.None,
                        RevocationMode = X509RevocationMode.NoCheck
                    };
                    var requestBinding = new Saml2PostBinding();
                    var logoutRequest = requestBinding.ReadSamlRequest(httpRequest, new Saml2LogoutRequest(saml2Configuration));

                    // validate sp
                    var saml2Partner = _applicationDbContext.Saml2Partners.Where(c => c.Issuer == logoutRequest.Issuer).FirstOrDefault();
                    if (saml2Partner == null)
                        return BadRequest();

                    if (saml2Partner.Type == "SP")
                    {
                        // validate logout request
                        var entityDescriptor = new EntityDescriptor();
                        entityDescriptor.ReadSPSsoDescriptorFromUrl(new Uri(saml2Partner.MetadataUrl));
                        
                        EventLog eventlog = new EventLog();
                        eventlog.Source = "Application";
                        eventlog.WriteEntry("Debug:" + saml2Partner.MetadataUrl);

                        logoutRequest.SignatureValidationCertificates = entityDescriptor.SPSsoDescriptor.SigningCertificates.ToList();
                        requestBinding.Unbind(Request.ToGenericHttpRequest(), logoutRequest);

                        // delete user session
                        var sessionIndex = TempData["SessionIndex"].ToString();
                        if (logoutRequest.SessionIndex != sessionIndex)
                            return NoContent();
                        await _signInManager.SignOutAsync();



                        // send saml response
                        var responseBinding = new Saml2PostBinding();
                        var logouResponse = new Saml2LogoutResponse(new Saml2Configuration())
                        {
                            InResponseTo = logoutRequest.Id,
                            Status = Saml2StatusCodes.Success,
                            Destination = entityDescriptor.SPSsoDescriptor.SingleLogoutServices.First().Location,
                            SessionIndex = logoutRequest.SessionIndex
                        };
                        return responseBinding.Bind(logouResponse).ToActionResult();

                    }
                    else if (saml2Partner.Type == "IdP")
                    {
                        // validate logout request
                        var entityDescriptor = new EntityDescriptor();
                        entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(saml2Partner.MetadataUrl));
                        logoutRequest.SignatureValidationCertificates = entityDescriptor.IdPSsoDescriptor.SigningCertificates.ToList();
                        requestBinding.Unbind(Request.ToGenericHttpRequest(), logoutRequest);

                        // delete user session
                        var sessionIndex = TempData["SessionIndex"].ToString();
                        if (logoutRequest.SessionIndex != sessionIndex)
                            return NoContent();
                        await _signInManager.SignOutAsync();

                        // send saml response
                        var responseBinding = new Saml2PostBinding();
                        var logouResponse = new Saml2LogoutResponse(new Saml2Configuration())
                        {
                            InResponseTo = logoutRequest.Id,
                            Status = Saml2StatusCodes.Success,
                            Destination = entityDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location,
                            SessionIndex = logoutRequest.SessionIndex
                        };
                        return responseBinding.Bind(logouResponse).ToActionResult();


                    }


                }
                else if (httpRequest.Form.AllKeys.Contains("SAMLResponse"))
                {
                    return RedirectToAction("Index", "Home");
                }
            }
            else if (httpRequest.Method == "GET")
            {
                if (httpRequest.Query.AllKeys.Contains("SAMLRequest"))
                {
                    // read saml logout request from sp
                    var saml2Configuration = new Saml2Configuration() 
                    {
                        CertificateValidationMode = X509CertificateValidationMode.None,
                        RevocationMode = X509RevocationMode.NoCheck
                    };
                    var requestBinding = new Saml2RedirectBinding();
                    var logoutRequest = requestBinding.ReadSamlRequest(httpRequest, new Saml2LogoutRequest(saml2Configuration));

                    // validate sp
                    var saml2Partner = _applicationDbContext.Saml2Partners.Where(c => c.Issuer == logoutRequest.Issuer).FirstOrDefault();
                    if (saml2Partner == null)
                        return BadRequest();

                    if(saml2Partner.Type == "SP")
                    {
                        // validate logout request
                        var entityDescriptor = new EntityDescriptor();
                        entityDescriptor.ReadSPSsoDescriptorFromUrl(new Uri(saml2Partner.MetadataUrl));
                        logoutRequest.SignatureValidationCertificates = entityDescriptor.SPSsoDescriptor.SigningCertificates.ToList();
                        logoutRequest.SignatureAlgorithm = httpRequest.Query["SigAlg"];
                        requestBinding.Unbind(Request.ToGenericHttpRequest(), logoutRequest);

                        // delete user session
                        var sessionIndex = TempData["SessionIndex"].ToString();
                        if (logoutRequest.SessionIndex != sessionIndex)
                            return NoContent();
                        await _signInManager.SignOutAsync();



                        // send saml response
                        var responseBinding = new Saml2RedirectBinding();
                        var logouResponse = new Saml2LogoutResponse(new Saml2Configuration())
                        {
                            InResponseTo = logoutRequest.Id,
                            Status = Saml2StatusCodes.Success,
                            Destination = entityDescriptor.SPSsoDescriptor.SingleLogoutServices.First().Location,
                            SessionIndex = logoutRequest.SessionIndex
                        };
                        return responseBinding.Bind(logouResponse).ToActionResult();

                    }
                    else if(saml2Partner.Type == "IdP")
                    {
                        // validate logout request
                        var entityDescriptor = new EntityDescriptor();
                        entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(saml2Partner.MetadataUrl));
                        logoutRequest.SignatureValidationCertificates = entityDescriptor.IdPSsoDescriptor.SigningCertificates.ToList();
                        logoutRequest.SignatureAlgorithm = httpRequest.Query["SigAlg"];
                        requestBinding.Unbind(Request.ToGenericHttpRequest(), logoutRequest);

                        // delete user session
                        var sessionIndex = TempData["SessionIndex"].ToString();
                        if (logoutRequest.SessionIndex != sessionIndex)
                            return NoContent();
                        await _signInManager.SignOutAsync();

                        // send saml response
                        var responseBinding = new Saml2RedirectBinding();
                        var logouResponse = new Saml2LogoutResponse(new Saml2Configuration())
                        {
                            InResponseTo = logoutRequest.Id,
                            Status = Saml2StatusCodes.Success,
                            Destination = entityDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location,
                            SessionIndex = logoutRequest.SessionIndex
                        };
                        return responseBinding.Bind(logouResponse).ToActionResult();


                    }



                }
                else if (httpRequest.Query.AllKeys.Contains("SAMLResponse"))
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    // interactive sign out from this application
                    // validate sessionIndex
                    var spsessionIndex = TempData["SessionIndex"]?.ToString();
                    if (string.IsNullOrEmpty(spsessionIndex))
                    {
                        return RedirectToAction("Index", "Home");
                    }
                    var referer = Request.Headers["Referer"].ToString();
                    string entityLogount = _configuration["Saml2EntityId"] + "/Account/Logout";
                    if (!referer.Contains(entityLogount))
                    {
                        return RedirectToAction("Index", "Home");
                    }
                    
                    // try to logout Idp.
                    var saml2Configuration = new Saml2Configuration() 
                    {
                        CertificateValidationMode = X509CertificateValidationMode.None,
                        RevocationMode = X509RevocationMode.NoCheck
                    };
                    saml2Configuration.AllowedAudienceUris.Add(_configuration["Saml2EntityId"]);

                    var partner = TempData["Partner"].ToString();
                    var saml2Partner = _applicationDbContext.Saml2Partners.Where(c => c.Issuer == partner).FirstOrDefault();

                    if(saml2Partner.Type == "IdP")
                    {
                        var entityDescriptor = new EntityDescriptor();
                        entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(saml2Partner.MetadataUrl));

                        if (entityDescriptor.IdPSsoDescriptor != null)
                        {
                            saml2Configuration.AllowedIssuer = entityDescriptor.EntityId;
                            saml2Configuration.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                            saml2Configuration.SingleLogoutDestination = entityDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location;
                            saml2Configuration.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
                            if (entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.HasValue)
                                saml2Configuration.SignAuthnRequest = entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.Value;
                        }

                    }
                    else if(saml2Partner.Type == "SP")
                    {
                        var entityDescriptor = new EntityDescriptor();
                        entityDescriptor.ReadSPSsoDescriptorFromUrl(new Uri(saml2Partner.MetadataUrl));

                        if (entityDescriptor.SPSsoDescriptor != null)
                        {
                            saml2Configuration.AllowedIssuer = entityDescriptor.EntityId;
                            saml2Configuration.AllowedAudienceUris.Add(entityDescriptor.EntityId);
                            saml2Configuration.SingleLogoutDestination = entityDescriptor.SPSsoDescriptor.SingleLogoutServices.First().Location;
                            saml2Configuration.SignatureValidationCertificates.AddRange(entityDescriptor.SPSsoDescriptor.SigningCertificates);
                        }

                    }



                    saml2Configuration.Issuer = _configuration["Saml2EntityId"];
                    saml2Configuration.SigningCertificate = RetrieveIdpCert();

                    var binding = new Saml2PostBinding();
                    var saml2LogoutRequest = new Saml2LogoutRequest(saml2Configuration, User);
                    saml2LogoutRequest.SessionIndex = spsessionIndex;
                    saml2LogoutRequest.NameId = new Saml2NameIdentifier(TempData["UserName"].ToString());
                    return binding.Bind(saml2LogoutRequest).ToActionResult();

                }

            }
            return BadRequest();
        }

        public IActionResult MetaData()
        {
            var cert = RetrieveIdpCert();
            var saml2Configuration = new Saml2Configuration()
            {
                Issuer = _configuration["Saml2EntityId"],
                SigningCertificate = cert,
                SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                SingleSignOnDestination = new Uri(_configuration["Saml2EntityId"] + "/saml2/login"),
                SingleLogoutDestination = new Uri(_configuration["Saml2EntityId"] + "/saml2/logout"),
                
                
            };
            var entityDescriptor = new EntityDescriptor(saml2Configuration, true);
            entityDescriptor.ValidUntil = 365;
            entityDescriptor.IdPSsoDescriptor = new IdPSsoDescriptor
            {
                SigningCertificates = new X509Certificate2[]
                {
                    saml2Configuration.SigningCertificate
                },
                EncryptionCertificates = new X509Certificate2[]
                {
                    saml2Configuration.SigningCertificate
                },
                WantAuthnRequestsSigned = false,
                EncryptionMethods = new[] { new EncryptionMethodType() { Algorithm = saml2Configuration.SignatureAlgorithm } },
                SingleSignOnServices = new SingleSignOnService[] { new SingleSignOnService() { Binding = ProtocolBindings.HttpRedirect, Location = saml2Configuration.SingleSignOnDestination } },
                SingleLogoutServices = new SingleLogoutService[] { new SingleLogoutService() { Binding = ProtocolBindings.HttpPost, Location = saml2Configuration.SingleLogoutDestination } },
                NameIDFormats = new Uri[] { NameIdentifierFormats.Email },
                
                
            };
            entityDescriptor.SPSsoDescriptor = new SPSsoDescriptor
            {
                WantAssertionsSigned = true,
                SigningCertificates = new X509Certificate2[]
                {
                    saml2Configuration.SigningCertificate
                },
                SingleLogoutServices = new SingleLogoutService[] { new SingleLogoutService() { Binding = ProtocolBindings.HttpPost, Location = saml2Configuration.SingleLogoutDestination } },
                NameIDFormats = new Uri[] { NameIdentifierFormats.Email },
                AssertionConsumerServices = new AssertionConsumerService[]
                {
                    new AssertionConsumerService{Binding=ProtocolBindings.HttpPost, Location = new Uri(_configuration["Saml2EntityId"] + "/saml2/assertionConsumerservice")}
                }
            };


            var metadata = new Saml2Metadata(entityDescriptor).CreateMetadata();
            return metadata.ToActionResult();

        }

        #region
        private X509Certificate2 RetrieveIdpCert()
        {

            var kvUri = _configuration["KeyVaultName"];
            var certClient = new CertificateClient(new Uri(kvUri), new DefaultAzureCredential());
            KeyVaultCertificateWithPolicy certificate = certClient.GetCertificateAsync(_configuration["SignCertName"]).GetAwaiter().GetResult();
            var secretClient = new SecretClient(new Uri(kvUri), new DefaultAzureCredential());
            KeyVaultSecret secret = secretClient.GetSecretAsync(certificate.SecretId.Segments[2] + certificate.SecretId.Segments[3]).GetAwaiter().GetResult();

            var cert = new X509Certificate2(Convert.FromBase64String(secret.Value));

            return cert;
        }

        private void SaveSaml2Info(string relayState, string inResponseTo, string destination, string issuer)
        {
            TempData["RelayState"] = relayState;
            TempData["InResponseTo"] = inResponseTo;
            TempData["Destination"] = destination;
            TempData["Issuer"] = issuer;
        }

        private Saml2Response CreateSaml2Response(Saml2Configuration saml2Configuration, string inResponseTo, string destination, string issuer)
        {
            var saml2AuthnResponse = new Saml2AuthnResponse(saml2Configuration)
            {

                InResponseTo = new Saml2Id(inResponseTo),
                Status = Saml2StatusCodes.Success,
                Destination = new Uri(destination)
            };
            var sessionIndex = Guid.NewGuid().ToString();
            saml2AuthnResponse.SessionIndex = sessionIndex;
            TempData["SessionIndex"] = sessionIndex;

            var claimIdentity = User.Identity as ClaimsIdentity;
            var immutableId = claimIdentity.Claims.Where(c => c.Type == "immutableId").Select(c => c.Value).Single().ToString();
            saml2AuthnResponse.NameId = new Saml2NameIdentifier(immutableId, NameIdentifierFormats.Persistent);
            saml2AuthnResponse.ClaimsIdentity = claimIdentity;
            var token = saml2AuthnResponse.CreateSecurityToken(issuer, subjectConfirmationLifetime: 5, issuedTokenLifetime: 60);

            return saml2AuthnResponse;

        }

        #endregion

    }
}
