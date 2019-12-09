using Microsoft.AspNetCore.Authentication;

namespace Authentication.Hash
{
    public class HashAuthenticationOptions: AuthenticationSchemeOptions
    {
        public string Secret { get; set; }

        public HashAlgorithm Algorithm { get; set; }
    }

    public enum HashAlgorithm
    {
        Sha1,
        Sha256,
        Sha512
    }
}