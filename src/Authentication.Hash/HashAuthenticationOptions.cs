using Authentication.Hash.Events;
using Microsoft.AspNetCore.Authentication;

namespace Authentication.Hash
{
    public class HashAuthenticationOptions: AuthenticationSchemeOptions
    {
        public new HashAuthenticationEvents Events
        {
            get { return (HashAuthenticationEvents)base.Events; }

            set { base.Events = value; }
        }


        public string Secret { get; set; }

        public Sha Algorithm { get; set; }
    }

    public enum Sha
    {
        Sha1,
        Sha256,
        Sha512
    }
}