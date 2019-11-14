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

## TODO

* Groups support
* HTTP headers support
