using System;
using Microsoft.AspNetCore.Authentication;

namespace Authentication.Hash
{
    public static class HashAuthenticationExtensions
    {
        public static AuthenticationBuilder AddHash(this AuthenticationBuilder builder, Action<HashAuthenticationOptions> options = null)
        {
            return builder.AddScheme<HashAuthenticationOptions, HashAuthenticationHandler>(HashAuthenticationDefaults.AuthenticationScheme, options);
        }
    }
}