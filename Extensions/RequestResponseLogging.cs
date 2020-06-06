using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using System.IO;
using MyScimApp.Models;
using MyScimApp.Data.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Net;

namespace MyScimApp.Extensions
{
    public class RequestResponseLogging
    {
        private readonly RequestDelegate _requestDelegate;
        public RequestResponseLogging(RequestDelegate requestDelegate)
        {
            _requestDelegate = requestDelegate;
        }
        public async Task Invoke(HttpContext httpContext)
        {

            using (var applicationDbContext = httpContext.RequestServices.GetRequiredService<ApplicationDbContext>())
            {
                // for request logging.
                var requestLog = await FormatRequest(httpContext.Request);
                applicationDbContext.accessLogs.Add(requestLog);

                // for response logging.
                var originalBodyStream = httpContext.Response.Body;
                using (var responseBody = new MemoryStream())
                {
                    httpContext.Response.Body = responseBody;
                    await _requestDelegate(httpContext);

                    var responseLog = await FormatResponse(httpContext.Response);
                    await responseBody.CopyToAsync(originalBodyStream);

                    applicationDbContext.accessLogs.Add(responseLog);

                    applicationDbContext.SaveChanges();

                }
            }
            
        }

        private async Task<AccessLog> FormatRequest(HttpRequest httpRequest)
        {
            var body = httpRequest.Body;
            httpRequest.EnableBuffering();
            var buffer = new byte[Convert.ToInt32(httpRequest.ContentLength)];
            await httpRequest.Body.ReadAsync(buffer, 0, buffer.Length);
            var bodyAsText = UTF8Encoding.UTF8.GetString(buffer);
            httpRequest.Body.Position = 0;

            var requestHeaders = httpRequest.Headers.ToList();
            var requestHeaderBuilder = new StringBuilder();
            foreach(var requestHeader in requestHeaders)
            {
                requestHeaderBuilder.Append($"{requestHeader.Key}: {string.Join(",", requestHeader.Value)}   {Environment.NewLine}");
            }
            
            var requestLog = new AccessLog
            {
                DateTime = DateTime.UtcNow,
                Type = "Request",
                HttpMethod = httpRequest.Method,
                Headers = requestHeaderBuilder.ToString(),
                AbsoluteUrl = $"{httpRequest.Scheme}://{httpRequest.Host}{httpRequest.Path}{WebUtility.UrlDecode(httpRequest.QueryString.ToString())}",
                Body = bodyAsText
            };


            return requestLog;
        }
        private async Task<AccessLog> FormatResponse(HttpResponse httpResponse)
        {
            httpResponse.Body.Seek(0, SeekOrigin.Begin);
            string bodyAsText = await new StreamReader(httpResponse.Body).ReadToEndAsync();
            httpResponse.Body.Seek(0, SeekOrigin.Begin);

            var responseHeaders = httpResponse.Headers.ToList();
            var responseHeaderBuilder = new StringBuilder();
            foreach (var responseHeader in responseHeaders)
            {
                responseHeaderBuilder.Append($"{responseHeader.Key}: {string.Join(",", responseHeader.Value)}   {Environment.NewLine}");
            }

            var responseLog = new AccessLog
            {
                DateTime = DateTime.UtcNow,
                Type = "Response",
                Headers = responseHeaderBuilder.ToString(),
                StatusCode = httpResponse.StatusCode.ToString(),
                Body = bodyAsText,
            };

            return responseLog;
        }
    }
}
