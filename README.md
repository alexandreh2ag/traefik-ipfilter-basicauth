# Ip Filter - Basic auth

Ip Filter - Basic auth is a middleware plugin for [Traefik](https://github.com/traefik/traefik) which try to authorize client by IP address or at least by Basic auth.

## Configuration

### Static

```toml
[pilot]
  token = "xxxx"

[experimental.plugins.ipFilter_basicAuth]
  modulename = "github.com/alexandreh2ag/traefik-ipfilter-basicauth"
  version = "vX.X.X"
```

### Dynamic

To configure the `Ip Filter - Basic auth` plugin you should create a [middleware](https://doc.traefik.io/traefik/middlewares/overview/) in
your dynamic configuration as explained [here](https://doc.traefik.io/traefik/middlewares/overview/).

You must define at least one source range IP and one user from configuration or file.

The configuration of middleware is quite similar then traefik middlewares ([IPWhiteList](https://doc.traefik.io/traefik/middlewares/http/ipwhitelist/) / [BasicAuth](https://doc.traefik.io/traefik/middlewares/http/basicauth/)).

```yaml
http:
  middlewares:
    my-ipFilter_basicAuth:
      plugin:
        ipFilter_basicAuth:
          basicAuth:
            realm: "Realm"
            usersFile: "/path/to/my/usersfile"
            users:
              - traefik:$apr1$imy7rq16$PbXJYj5lsqZ71HoIBfm/T0 # traefik / traefik
            headerField: "X-WebAuth-User"
            removeHeader: true
          ipWhiteList:
            sourceRange:
              - "127.0.0.1"
              - "10.0.0.1/32"
```
