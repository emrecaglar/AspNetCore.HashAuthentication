using System;
using System.Security.Claims;
using Authentication.Hash;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Authentication.Hash.Events
{
    public class ValidateCredentialsContext : ResultContext<HashAuthenticationOptions>
    {
        public ValidateCredentialsContext(
            HttpContext context,
            AuthenticationScheme scheme,
            HashAuthenticationOptions options)
            : base(context, scheme, options)
        {
            Principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
            {
                new Claim("hash", context.Request.Headers["Authorization"].ToString().Substring(scheme.Name.Length).Trim())
            }, scheme.Name));
        }

        public string Hash { get; set; }
    }
}