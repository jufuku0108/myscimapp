using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
//using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Configuration;
//using Microsoft.Extensions.Configuration.AzureKeyVault;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Azure.Identity;
using Azure.Extensions.AspNetCore.Configuration.Secrets;

namespace MyScimApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((context, configBuilder) => {
                    var builtConfig = configBuilder.Build();
                    var options = new DefaultAzureCredentialOptions();
                    options.TenantId = builtConfig["TenantId"];
                    configBuilder.AddAzureKeyVault(
                        new Uri(builtConfig["KeyVaultName"]),
                        new DefaultAzureCredential(options));
                
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
