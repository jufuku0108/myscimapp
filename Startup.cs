using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using MyScimApp.Models;
using Microsoft.AspNetCore.Identity;
using MyScimApp.Extensions;
using MyScimApp.Data.Users;
using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.CodeAnalysis.Options;
using System.Reflection;
using Microsoft.Azure.Services.AppAuthentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore.Query;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using System.Diagnostics;

namespace MyScimApp
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddControllersWithViews()
                .AddNewtonsoftJson();

            services.AddCors(options =>
            {
                options.AddPolicy("AllowMyOrigin",
                    builder => builder.WithOrigins(Configuration["CorsOrigin"])
                        .AllowAnyHeader()
                        .AllowAnyMethod());
            });

            services.AddDbContext<ApplicationDbContext>(options =>
            {
                var sql = Configuration["DefaultConnection"];
                options.UseSqlServer(Configuration["DefaultConnection"]);
            });


            services.AddIdentity<ApplicationUser, IdentityRole>(options => {
                options.SignIn.RequireConfirmedEmail = true;
                })
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            // identity server 4 settings.
            var kvUri = Configuration["KeyVaultName"];
            var options = new DefaultAzureCredentialOptions();
            options.TenantId = Configuration["TenantId"];
            var certClient = new CertificateClient(new Uri(kvUri), new DefaultAzureCredential(options));
            KeyVaultCertificateWithPolicy certificate = certClient.GetCertificateAsync(Configuration["SignCertName"]).GetAwaiter().GetResult();
            var secretClient = new SecretClient(new Uri(kvUri), new DefaultAzureCredential(options));
            KeyVaultSecret secret = secretClient.GetSecretAsync(certificate.SecretId.Segments[2] + certificate.SecretId.Segments[3]).GetAwaiter().GetResult();
            var cert = new X509Certificate2(Convert.FromBase64String(secret.Value));



            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;
            services.AddIdentityServer(options =>
            {
                options.UserInteraction.ConsentUrl = "/Account/Consent";

            })
                .AddSigningCredential(cert)
                .AddOperationalStore(options =>
                {
                    options.ConfigureDbContext = builder =>
                       builder.UseSqlServer(Configuration["DefaultConnection"], db => db.MigrationsAssembly(migrationsAssembly));
                    options.EnableTokenCleanup = true;
                    options.TokenCleanupInterval = 30;
                })
                .AddConfigurationStore(options =>
                {
                    options.ConfigureDbContext = builder =>
                        builder.UseSqlServer(Configuration["DefaultConnection"], db => db.MigrationsAssembly(migrationsAssembly));
                })
                .AddAspNetIdentity<ApplicationUser>()
                //.AddProfileService<ProfileService>()
                ;

            services.AddAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme)
                .AddFacebook(options =>
                {
                    options.SignInScheme = IdentityConstants.ExternalScheme;
                    options.ClientId = Configuration["FacebookClientId"];
                    options.ClientSecret = Configuration["FaceboockClientSecret"];
                })
                .AddGoogle(options =>
                {
                    options.SignInScheme = IdentityConstants.ExternalScheme;
                    options.ClientId = Configuration["GoogleClientId"];
                    options.ClientSecret = Configuration["GoogleClientSecret"];
                })
                .AddTwitter(options =>
                {
                    options.SignInScheme = IdentityConstants.ExternalScheme;
                    options.ConsumerKey = Configuration["TwitterClientId"];
                    options.ConsumerSecret = Configuration["TwitterClientSecret"];
                })
                .AddOpenIdConnect("AzureAD", "Azure AD Authentication", options =>
                {
                    options.ClientId = Configuration["AzureADClientId"];
                    options.ClientSecret = Configuration["AzureADClientSecret"];
                    options.Authority = "https://login.microsoftonline.com/common/v2.0/";
                    options.ResponseType = "code";
                    options.Prompt = "select_account";
                    options.Scope.Add("profile");
                    options.Scope.Add("openid");
                    options.Scope.Add("email");
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false
                    };
                    options.CallbackPath = "/signin-microsoft";
                })
                .AddOpenIdConnect("ADFS", "AD FS Authentication", options =>
                {
                    options.ClientId = Configuration["ADFSClientId"];
                    options.ClientSecret = Configuration["ADFSClientSecret"];
                    options.Authority = "https://adfs.jfadm170.net/adfs/";
                    options.ResponseType = "code";
                    options.Scope.Add("profile");
                    options.Scope.Add("openid");
                    options.Scope.Add("email");
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false
                    };
                    options.CallbackPath = "/signin-adfs";
                    options.Prompt = "login";
                })
                ;
            

            services.AddScoped<Fido2Service>();

            services.ConfigureApplicationCookie(options =>
            {
                options.ExpireTimeSpan = TimeSpan.FromMinutes(40);
                options.SlidingExpiration = true ;
            });

            services.Configure<CookieTempDataProviderOptions>(options =>
            {
                options.Cookie.SameSite = SameSiteMode.None;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            });


        }
        

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, ILoggerFactory loggerFactory)
        {

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();

            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            //app.UseMiddleware<RequestResponseLogging>();

            app.UseIdentityServer();
            app.UseAuthorization();


            app.UseCors("AllowMyOrigin");

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
            DatabaseInitializer.SeedUserData(app, userManager, roleManager).Wait();
            DatabaseInitializer.SeedIdentityServerConfigurationData(app);
        }
    }
}
