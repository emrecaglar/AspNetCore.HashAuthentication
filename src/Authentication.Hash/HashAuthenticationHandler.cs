using Authentication.Hash.Events;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Authentication.Hash
{
    public class HashAuthenticationHandler : AuthenticationHandler<HashAuthenticationOptions>
    {
        public HashAuthenticationHandler(
            IOptionsMonitor<HashAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        protected new HashAuthenticationEvents Events
        {
            get { return (HashAuthenticationEvents)base.Events; }
            set { base.Events = value; }
        }

        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new HashAuthenticationEvents());

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string authorizationHeader = Request.Headers["Authorization"];

            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return AuthenticateResult.NoResult();
            }

            if (!authorizationHeader.StartsWith(HashAuthenticationDefaults.AuthenticationScheme + ' ', StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticateResult.NoResult();
            }

            string credentials = authorizationHeader.Substring(HashAuthenticationDefaults.AuthenticationScheme.Length).Trim();

            try
            {
                var validateCredentialsContext = new ValidateCredentialsContext(Context, Scheme, Options)
                {
                    Secret = Options.Secret,
                    Algorithm = Options.Algorithm,
                    AuthorizationHeader = credentials
                };

                string hashed = GetHash(Options.Secret, Options.Algorithm);

                if (hashed.Equals(credentials, StringComparison.OrdinalIgnoreCase))
                {
                    var ticket = new AuthenticationTicket(validateCredentialsContext.Principal, Scheme.Name);

                    await Events.HashValidated(validateCredentialsContext);

                    if (validateCredentialsContext.Result != null)
                    {
                        return validateCredentialsContext.Result;
                    }

                    return AuthenticateResult.Success(ticket);
                }
                else
                {
                    await Events.AuthenticationFailed(new HashAuthenticationFailedContext(Context, Scheme, Options)
                    {
                        Exception = new Exception("Wrong hash")
                    });

                    if (validateCredentialsContext.Result != null)
                    {
                        return validateCredentialsContext.Result;
                    }

                    return AuthenticateResult.Fail("Wrong hash");
                }
            }
            catch (Exception ex)
            {
                var authenticationFailedContext = new HashAuthenticationFailedContext(Context, Scheme, Options)
                {
                    Exception = ex
                };

                await Events.AuthenticationFailed(authenticationFailedContext);

                if (authenticationFailedContext.Result != null)
                {
                    return authenticationFailedContext.Result;
                }

                throw;
            }
        }

        private string GetHash(string secret, Sha algorithm)
        {
            HashAlgorithm hashAlgorithm;

            switch (algorithm)
            {
                case Sha.Sha1:
                    hashAlgorithm = SHA1.Create();
                    break;
                case Sha.Sha256:
                    hashAlgorithm = SHA256.Create();
                    break;
                case Sha.Sha512:
                    hashAlgorithm = SHA512.Create();
                    break;
                default:
                    hashAlgorithm = SHA256.Create();
                    break;
            }

            byte[] bytes = hashAlgorithm.ComputeHash(Encoding.ASCII.GetBytes(secret));

            return string.Concat(bytes.Select(x => x.ToString("X2")).ToArray());
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = 401;

            string realm = $"Hash realm=\"{Request.Headers[HeaderNames.Authorization]}\", error=\"invalid_hash\"";

            Response.Headers.Append(HeaderNames.WWWAuthenticate, realm);

            return Task.CompletedTask;
        }
    }
}