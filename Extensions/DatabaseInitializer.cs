using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using MyScimApp.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore.Metadata.Internal;

namespace MyScimApp.Extensions
{

    public static class DatabaseInitializer
    {
        public static async Task SeedUserData(IApplicationBuilder app, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            var configuration = app.ApplicationServices.GetService<IConfiguration>();
            var adminUserName = configuration["AdminUserName"];
            var adminUserPassowrd = configuration["AdminUserPassword"];

            if (!roleManager.RoleExistsAsync("Admin").Result)
            {
                var adminRole = new IdentityRole { Name = "Admin", NormalizedName = "ADMIN" };
                var adminRoleResult = await roleManager.CreateAsync(adminRole);
            }
            if (!roleManager.RoleExistsAsync("User").Result)
            {
                var userRole = new IdentityRole { Name = "User", NormalizedName = "USER" };
                var userRoleResult = await roleManager.CreateAsync(userRole);
            }
            

            if(userManager.FindByNameAsync(adminUserName).Result == null)
            {
                var adminUser = new ApplicationUser { UserName = adminUserName, Email = adminUserName, EmailConfirmed = true };
                var adminUserResult = await userManager.CreateAsync(adminUser, adminUserPassowrd);
            }
            var roledAdminUser = await userManager.FindByNameAsync(adminUserName);
            if (!userManager.IsInRoleAsync(roledAdminUser, "Admin").Result)
            {
                var roledAdminUserResult = await userManager.AddToRoleAsync(roledAdminUser, "Admin");
            }
        }
        public static void SeedIdentityServerConfigurationData(IApplicationBuilder app)
        
        {

            using (var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
            {
                var context = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
                if (!context.Clients.AsQueryable().Where(c => c.Description == "System").Any())
                {
                    foreach(var client in IdentityServerConfig.GetClients(app))
                    {
                        context.Clients.Add(client.ToEntity());
                    }
                    context.SaveChanges();
                }
                if (!context.IdentityResources.Any())
                {
                    foreach(var resource in IdentityServerConfig.GetIdentityResources())
                    {
                        context.IdentityResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }
                if (!context.ApiResources.Any())
                {
                    foreach(var resource in IdentityServerConfig.GetApiResources(app))
                    {
                        context.ApiResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }
                if (!context.ApiScopes.Any())
                {
                    foreach(var scope in IdentityServerConfig.GetApiScopes())
                    {
                        context.ApiScopes.Add(scope.ToEntity());
                    }
                    context.SaveChanges();
                }

            }
        }
    }
}
