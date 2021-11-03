# 14.0 Custom external authentication provider samples
This is the recommended approach when integrating external identity proviers with custom logic.
| :exclamation: THE SAMPLE HERE IS VALID ONLY IF YOU ARE USING THE *DEFAULT* AUTHENTICATION PROTOCOL.   |
|--------------------------------------------------------------------------------------------------------|

Sitefinity ships out of box (OOB) with several external authentication providers (EAP) for several popular Identity Providers (IP or sometimes called STS) like Google, Facebook, Microsoft. It also has one configurable generic EIP for authenticating with systems that follow the widely adopted OpenID Connect (OIDC) authentication protocol. Customizing the OIDC provider is described in this article: [Implement custom external identity providers](https://www.progress.com/documentation/sitefinity-cms/for-developers-implement-custom-external-identity-providers)

![image2021-9-14_13-3-35](https://user-images.githubusercontent.com/56825414/140044202-9263d431-9c17-4771-a8f3-06868b628765.png)

If you cannot use any of the OOB external authentication providers, you can implement a fully custom one by following the samples in this repo. Please note that for the purpose of the demo the samples here are not for production use as there are additional security implementations omitted for brievity.

The job of the EAP is to authenticate the user and then pass a claims based identity to Sitefinity with a few required claims. The repo contains two samples - one where the login page is on a remote server (Remote Login) and one where the login page is in Sitefinity and credentials provided by the user are sent to a remote server for verification (Local Login).
## Sample 1 - Remote Login
1. Create the configuration class - it is used to contain custom settings that you might want to configure via advanced settings view
2. ```
using Microsoft.Owin.Security;

namespace AutehnticationSamples
{
    public class RemoteLoginExternalAuthenticationProviderOptions : AuthenticationOptions
    {
        public RemoteLoginExternalAuthenticationProviderOptions(string authenticationType) : base(authenticationType)
        {
        }

        public string IdentityProviderAddress { get; set; }
        public string SignInAsAuthenticationType { get; set; }
    }
}``
