using System;
using Authentication.Hash;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Authentication.Hash.Events
{
    public class HashAuthenticationFailedContext: ResultContext<HashAuthenticationOptions>
    {
        public HashAuthenticationFailedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            HashAuthenticationOptions options)
            : base(context, scheme, options)
        {
        }

        public Exception Exception { get; set; }
    }
}