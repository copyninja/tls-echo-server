# About  #

This repository contains my attempt to add TLS support to legacy code with
*openssl* and *gnutls* libraries. 

  * server.c: Is the code mimicking the original legacy code I had to work with
  * openssl_main.c: Is the attempt of using openssl library with this legacy
    code.
  * gnutls_main.c: Is the attempt of using gnutls library with this legacy code.
  
Legacy code is a forking server which on receiving new connection forks and
creates a child which will then process the connection. It uses select to check
for the data on the connection.

After reading many articles on how to add TLS support and experimenting I wrote
this code. I'm not sure if this is the correct way to use SSL or not but the
code works and also is free of any memory leaks.
  
# Compiling #

Makefile for the project is written in such a way that it can compile any one
version of the server. Below is how you can compile legacy code

``` shell
$ make
or 
$ make SSL=none
```
For compiling OpenSSL version of the server you need to pass `openssl` to `SSL`
variable in following format

``` shell
make SSL=openssl
```
For compiling GnuTLS version of the server you need to pass `gnutls` to `SSL`
variable in following format.

``` shell
make SSL=gnutls
```

# Creating certificate #

For running server in TLS mode it expects presence of *cert.pem* and
*privkey.pem* file in the same directory. To generate self signed certificate
using openssl command.

``` shell
openssl req -x509 -newkey rsa:2048 -keyout privkey.pem -out cert.pem -days 365 -nodes
```

Alternatively you can call `run` target of Makefile to do this and run the
binary.

```shell
make run SSL=openssl
```

# Communicating with Server #

You can use `telnet` command to communicate with non TLS server. After you are
done send *quit* message to server to end the session.

## Communicating with TLS server ##

For communicating with TLS version of the server you would need to use either
`openssl` or `gnutls-cli` command. Below are sample commands. 

```shell
openssl s_client -connect localhost:50000
gnutls-cli -p 50000 localhost --insecure
```

`--insecure` is needed for `gnutls-cli` to work with self signed certificate. As
before use *quit* message to disconnect from the server.



# Known Issues/Bugs #

  * Server can be easily subjected to Denial of Service attack as it is not
    limiting number of concurrent connections. Since it is a proof of concept
    code to learn the additional logic is not added to limit concurrent
    connections. 
  * If you input 8192 bytes data server will echo only 4096 data back. I'm not
    able to go in depth to understand why is this happening. This issue is
    common for both TLS and non TLS version.

# License #

Code is distributed under GPLv3 or later. You are free to modify re-distribute
the code under terms of GPLv3 or later.
