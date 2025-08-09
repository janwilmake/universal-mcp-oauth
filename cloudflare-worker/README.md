If you pass any URL, we need to use the MCP-standardized way of discovering oauth. If possible, direct user to signup/login with client. Credentials should be stored in central store. This in itself is super valuable and should be plugable into any website.

# TODO:

- Fix https://github.com/janwilmake/simplerauth-provider (ensure that it actually works, was just a test. feels like its broken somehow)
- Test adding servers, see if it works here too
- After that, combine it with a allowing for non-authenticated MCP servers too; we should be able to connect with HTTP and see if connection could be established
- This whole thing should be included by default into my boilerplate (but using `xmoney-provider`) and never need .env anymore for anything - instead, user logs in into any paid APIs. At least, this must be a possibility.
