using MyScimApp.Data.Users;
using MyScimApp.Data.Users.Migrations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using MyScimApp.Models;
using Fido2NetLib;
using System.Text;

namespace MyScimApp.Extensions
{
    public class Fido2Service
    {
        private readonly ApplicationDbContext _applicationDbContext;
        public Fido2Service(ApplicationDbContext applicationDbContext)
        {
            _applicationDbContext = applicationDbContext;
        }
        public async Task<List<Fido2StoredCredential>> GetFido2StoredCredentialsByUserNameAsync(string userName)
        {
            var fido2StoredCredentials =  await _applicationDbContext.fido2StoredCredentials.Where(c => c.UserName == userName).ToListAsync();
            return fido2StoredCredentials;
        }
        public void RemoveFido2StoredCredentialsByUserNameAsync(string userName)
        {
            var fido2StoredCredentials =  _applicationDbContext.fido2StoredCredentials.Where(c => c.UserName == userName).ToList();
            foreach(var fido2StoredCredential in fido2StoredCredentials)
            {
                _applicationDbContext.Remove(fido2StoredCredential);
                _applicationDbContext.SaveChanges();
            }
        }
        public async Task<Fido2StoredCredential> GetFido2StoredCredentialsByCredentialIdAsync(byte[] credentialId)
        {
            var credentialIdString = Base64Url.Encode(credentialId);
            var fido2StoredCredential = await _applicationDbContext.fido2StoredCredentials.Where(c => c.DescriptorJson.Contains(credentialIdString)).FirstOrDefaultAsync();
            return fido2StoredCredential;
        }
        public async Task<List<Fido2StoredCredential>> GetFido2StoredCredentialsByUserHandleAsync(byte[] userHandle)
        {
            var fido2StoredCredentials = await _applicationDbContext.fido2StoredCredentials.Where(c => c.UserHandle == userHandle).ToListAsync();
            return fido2StoredCredentials;
        }

        public async Task<List<Fido2User>> GetFido2UsersByCredentialIdAsync(byte[] credentialId)
        {
            var credentialIdString = Base64Url.Encode(credentialId);
            var fido2StoredCredential = await _applicationDbContext.fido2StoredCredentials.Where(c => c.DescriptorJson.Contains(credentialIdString)).FirstOrDefaultAsync();
            if(fido2StoredCredential == null)
            {
                return new List<Fido2User>();
            }
            else
            {
                return await _applicationDbContext.Users
                    .Where(u => UTF8Encoding.UTF8.GetBytes(u.UserName).SequenceEqual(fido2StoredCredential.UserId))
                    .Select(u => new Fido2User
                    {
                        DisplayName = u.UserName,
                        Name = u.UserName,
                        Id = UTF8Encoding.UTF8.GetBytes(u.UserName)
                    })
                    .ToListAsync();
            }
        }

        public void AddFido2StoredCredential(Fido2StoredCredential fido2StoredCredential)
        {
            _applicationDbContext.fido2StoredCredentials.Add(fido2StoredCredential);
            _applicationDbContext.SaveChanges();
        }
        public async Task UpdateFido2StoredCredentialCounter(byte[] credentialId, uint signatureCounter)
        {
            var credentialIdString = Base64Url.Encode(credentialId);
            var fido2StoredCredential = await _applicationDbContext.fido2StoredCredentials.Where(c => c.DescriptorJson.Contains(credentialIdString)).FirstOrDefaultAsync();
            fido2StoredCredential.SignatureCounter = signatureCounter;
            await _applicationDbContext.SaveChangesAsync();
        }
    }
}
