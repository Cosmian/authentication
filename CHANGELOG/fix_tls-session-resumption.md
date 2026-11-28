## Bug Fixes

- Fix browsers failing with `ERR_SSL_PROTOCOL_ERROR` on their second connection to the OpenSSL HTTPS server: the TLS acceptor now sets a session id context, so TLS session resumption works with client-certificate verification enabled.
