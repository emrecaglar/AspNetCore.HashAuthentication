using System;
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
        }

        public string Hash { get; set; }
    }
}