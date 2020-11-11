# PyACME-Client
Implementation of an [RFC8555-ACMEv2](https://tools.ietf.org/pdf/rfc8555.pdf) client in Python. The app was written in Python, using all the non-native libraries present in the `compile` script, which is advised to be run before running the app.

## Command-line arguments 

The application should be run by making the `run` script executable and then passing it different command line arguments :

### Positional arguments:


#### Challenge type `{dns01 | http01}` (required)

Indicates which ACME challenge type the client should perform. Valid options are `dns01` and `http01` for the `dns-01` and `http-01` challenges, respectively.


### Keyword arguments:

#### `--dir DIR_URL` (required) 

`DIR_URL` is the directory URL of the ACME server that should be used.

#### `--record IPv4_ADDRESS` (required) 

`IPv4_ADDRESS` is the IPv4 address which must be returned by the DNS server for all A-record queries.

#### `--domain DOMAIN` (required, multiple) 

`DOMAIN` is the domain for  which to request the certificate. If multiple `--domain` flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net.

#### `--revoke` (optional)

If present, the application will immediately revoke the certificate after obtaining it.

### Example:

Consider the following invocation of run:

```run dns01 --dir https://example.com/dir --record 1.2.3.4 --domain example.com --domain test.clementsicard.com```

It should use the ACME server at the URL `https://example.com/dir` and perform the dns-01 challenge. The DNS server of the application will respond with `1.2.3.4` to all requests for A records. Once the certificate has been obtained, your application will start its certificate HTTPS server and install the obtained certificate in this server.
