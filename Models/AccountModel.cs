using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Fido2NetLib.Objects;
using Newtonsoft.Json;

namespace MyScimApp.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string UserType { get; set; }
        public virtual ICollection<ScimUser> ScimUser { get; set; }
    }

    public class RegisterViewModel
    {
        public string Username { get; set; }
        public string Password { get; set; }

        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
        public string ReturnUrl { get; set; }

    }
    public class LoginViewModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public bool RememberLogin { get; set; }
        public string ReturnUrl { get; set; }
    }
    public class ExternalLoginModel
    {
        public string Email { get; set; }

        public string LoginProvider { get; set; }
        public IEnumerable<Claim> Claims { get; set; }
    }
    public class LogoutViewModel
    {
        public string LogoutId { get; set; }
        public bool Confirmation { get; set; }
    }

    public class AuthenticationCode
    {
        public Guid AuthenticationCodeId { get; set; }
        public DateTime ExpiryDate { get; set; }
        public string Value { get; set; }
        public bool Active { get; set; }
    }
    public class AccountMfaInformation
    {
        public string SharedKey { get; set; }
        public string QrlCodeUri { get; set; }
        public string VerifyCode { get; set; }
    }
    public class LoginWithMfaViewModel
    {
        public string AuthenticationCode { get; set; }
        public bool RememberComputer { get; set; }
        public bool RememberMe { get; set; }
        public string ReturnUrl { get; set; }
    }

    public class DisableMfaViewModel
    {
        public bool Confirmation { get; set; }
    }

    public class DisableFido2ViewModel
    {
        public bool Confirmation { get; set; }
    }

    public class Fido2StoredCredential
    {
        public int Fido2StoredCredentialId { get; set; }
        public string UserName { get; set; }
        public byte[] UserId { get; set; }
        public byte[] PublicKey { get; set; }
        public byte[] UserHandle { get; set; }
        public uint SignatureCounter { get; set; }
        public string CredType { get; set; }
        public DateTime RegDate { get; set; }
        public Guid AaGuid { get; set; }
        [NotMapped]
        public PublicKeyCredentialDescriptor Descriptor
        {
            get { return string.IsNullOrEmpty(DescriptorJson) ? null : JsonConvert.DeserializeObject<PublicKeyCredentialDescriptor>(DescriptorJson); }
            set { DescriptorJson = JsonConvert.SerializeObject(value); }
        }
        public string DescriptorJson { get; set; }

    }
}
