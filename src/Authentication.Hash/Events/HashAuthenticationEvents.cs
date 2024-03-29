using System;
using System.Threading.Tasks;

namespace Authentication.Hash.Events
{
    public class HashAuthenticationEvents
    {
        public Func<HashAuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

        public Func<ValidateCredentialsContext, Task> OnValidated { get; set; } = context => Task.CompletedTask;

        public virtual Task AuthenticationFailed(HashAuthenticationFailedContext context) => OnAuthenticationFailed(context);

        public virtual Task HashValidated(ValidateCredentialsContext context) => OnValidated(context);
    }
}