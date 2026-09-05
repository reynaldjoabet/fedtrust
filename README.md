# fedtrust


## OpenID Federation
OpenID Federation deserves way more attention.

Traditional OIDC has been based on
"First register the other party, configure it, and establish trust."

OpenID Federation changes that.
- Proves trust relationships with JWT
- Traces the chain all the way to the Trust Anchor
- Builds trust even if IDP and RP haven't directly contracted
- Can automate client registration too

[identity-and-federation/openid-federation-1-0](https://developers.authlete.com/guides/flows-and-protocols/identity-and-federation/openid-federation-1-0)
