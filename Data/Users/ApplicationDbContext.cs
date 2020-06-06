using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using MyScimApp.Models;

namespace MyScimApp.Data.Users
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
        public DbSet<ScimUser> scimUsers { get; set; }
        public DbSet<ScimUserName> scimUserNames { get; set; }
        public DbSet<ScimUserPhoneNumber> scimUserPhoneNumbers { get; set; }
        public DbSet<ScimUserEmail> scimUserEmails { get; set; }
        public DbSet<ScimUserMetaData> scimUserMetaDatas { get; set; }
        public DbSet<ScimGroup> scimGroups { get; set; }
        public DbSet<ScimGroupMember> scimGroupMembers { get; set; }
        public DbSet<ScimGroupMetaData> scimGroupMetaDatas { get; set; }
        public DbSet<AccessLog> accessLogs { get; set; }
        public DbSet<AuthenticationCode> authenticationCodes { get; set; }
        public DbSet<Fido2StoredCredential> fido2StoredCredentials { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);


            modelBuilder.Entity<ScimUser>()
                .HasOne(su => su.Name)
                .WithOne(sun => sun.ScimUser)
                .HasForeignKey<ScimUserName>(sun => sun.ScimUserId);

            modelBuilder.Entity<ScimUserPhoneNumber>()
                .HasOne(sup => sup.ScimUser)
                .WithMany(su => su.PhoneNumbers);

            modelBuilder.Entity<ScimUserEmail>()
                .HasOne(sue => sue.ScimUser)
                .WithMany(su => su.Emails);

            modelBuilder.Entity<ScimUser>()
                .HasOne(su => su.Meta)
                .WithOne(sum => sum.ScimUser)
                .HasForeignKey<ScimUserMetaData>(sum => sum.ScimUserId);

            modelBuilder.Entity<ScimUser>()
                .HasOne(su => su.ApplicationUser)
                .WithMany(au => au.ScimUser)
                .HasForeignKey(su => su.ApplicationUserId);

            
            modelBuilder.Entity<ScimGroupMember>()
                .HasOne(sgm => sgm.ScimGroup)
                .WithMany(sg => sg.Members);


            modelBuilder.Entity<ScimGroup>()
                .HasOne(sg => sg.Meta)
                .WithOne(sgm => sgm.ScimGroup)
                .HasForeignKey<ScimGroupMetaData>(sgm => sgm.ScimGroupId);

            modelBuilder.Entity<Fido2StoredCredential>()
                .HasKey(f => f.Fido2StoredCredentialId);

        }

    }


}
