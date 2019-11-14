# nss_curl

This is a NSS module that uses cURL to fetch JSON from the remote host via http(s) and use that JSON to provide account information to a Linux system.

## Dependencies

* libssl-dev
* jansson-dev
* libcurl4-gnutls-dev

## Install

I tested the installation on Ubuntu 18.04, you will need to change Makefile maybe.

1. Clone git repo
1. Install dependencies
1. make
1. make install
1. Edit /etc/nsswitch.conf, add "curl" to the desired sections

```
passwd:         compat curl
group:          compat
```

## TODO

* Groups support
* HTTP headers support

## License

Copyright (c) 2019 Roman Yerin &lt;r.yerin@640kb.co.uk&gt;

Licensed under the 3-clause BSD license.
