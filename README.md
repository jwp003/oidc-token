# OIDC Token

A utility for receiving oauth2 access tokens from OIDC providers.

# Build

```
go build
```

Copy the binary to your `$PATH`.

# Usage

Create a config file at `~/.config/oidc-token/config.toml`. This file
will contain OIDC provider configurations. For example:

```toml
ListenAddress = "localhost:8888"

[[Providers]]
Name = "example"
URL = "https://auth.example.com"
ClientID = "example-client"
ClientSecret = "example-secret"
Scopes = ["openid", "profile", "email"]

[[Providers]]
Name = "another"
# ...
```

The `ListenAddress` controls the address on which `oidc-token` listens
for an oauth callback. It should be a free local `address:port`.

After that is a list of providers. The `Name` is just an alias which is used when running the utility. The other values are the OIDC parameters.

With the config file in place, you can run it like this:

```sh
oidc-token example
```

This will open a browser for you to login, and once the flow is complete, print the oauth2 access token to `stdout`.

Use with cURL or other utilities like this:

```sh
curl -H "Authorization: Bearer $(oidc-token example)" 'https://exmaple.com'
```

