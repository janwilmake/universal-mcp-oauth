In the last year or so, I've been creating loads of prototypes and POCs for my startup. I've now got over 700 repos in my account, and recently hit the 500 workers limit on Cloudflare. One recurring thing I keep experimenting with is OAuth because I believe there's some real opportunities to simplify it.

I haven't used third party oauth libraries (e.g. [better-auth](https://better-auth.com)) for a while, instead I started [simplerauth](https://simplerauth.com), which is a collection of auth snippets made from first principles, not indented to be used as one giant library but intended to be modular, so the total complexity of your app stays super small.

I've focused mostly on oauth with GitHub and with X, and one thing I ran into is that X OAuth is rather limiting. The X Developer plan only allows a single client, and that OAuth client only allows up to 10 callback URLs. Since I still really like X OAuth for the reason that my entire audience is on X, so they certainly have an account, I needed to find a way to scale this.

The answer is in creating a "OAuth Provider Proxy". This is what `simplerauth-provider` is. It proxies oauth login to X, but splits a single client_id+secret combo into unlimited client_ids and secrets.

One of the reasons I think there's innovation possible with oauth, is the fact that it MCP is now recommending a very specific oauth specification. Interestingly, they also recommend [dynamic client registration](https://datatracker.ietf.org/doc/html/rfc7591) which allows any client to register programmatically before initiating the oauth flow for a user. This reduces friction a lot when trying to scale your MCP client to hundreds of integrations.

But I noticed something interesting... Why would you allow programmatic client registration? Why do we need client registration in the first place? Well, the reason is that clients need to be trustable to be authorized access to a resource. OAuth was created with an ability for the resource owners to restrict which services could use their resource and which couldn't. But in the end, this isn't really used in many cases, is it? If I want a github oauth client, there's no verification process for that. In the end, it all comes down to the more important part of oauth, which is that the USER accepts and trusts the client to control the other service.

Another thing that I think is dumb, is that client registration allows setting all kinds of metadata such as name. The client_id is then oftenlike arbitrarily chosen by the server to be a random ID. This opens the door to deceiving people because you can just choose a name that is different from the name of the app that you redirect to after the user authorizes. This is also, I think, the main way in which people get hacked by oauth: they think they trust something based on the name, and then it [actually](https://x.com/thealexbanks/status/1892278711267053641) [gives](https://x.com/nearcyan/status/1888671601358778512) rights to a malicious server.

So basically, having dynamic client registration, albeit by humans or by machines, opens the door to error and deception.

What if we simplify the whole thing, and the client_id must be equal to the hostname to the sole redirect_uri? What if you could then just pass any `client_id` as long as the `redirect_uri` is on that same hostname?

Because in the end, the main thing that's important for the user to understand, is that they're giving rights of their account to another server, and that server is identified by a hostname.

Instead of `Do you grant access to {name}?` the oauth provider can now say `Do you grant access to {client_id}?`. Since the client_id is where the user gets redirected to afterwards (as this must match) the user can be sure that it's ok if they trust the domain. If we don't show a name, we don't need a name. If we don't need a name, we don't need registration, because we don't have any metadata to show. Well, we could add an icon, but why do we need to register the client for that? We could just take the favicon of the website itself.

Problem solved! I call it the "Domain-as-client-ID principle".

The Domain-as-client-ID principle has some interesting effects:

1. Any server can now integrate with your app without friction (as long as the user approves)
2. Any of your future apps can use the provider without having the friction of setting up a secret

Imagine a world now where every service did things like this. It would greatly simplify oauth and any app would immediately be able to ask for access to thousands of applications. As long as the user grants the client access to their other services, they can do stuff. This removes a ton of friction, and especially when we have intelligent clients in the age of AI, it's much needed.

I hope more people adopt this pattern.
