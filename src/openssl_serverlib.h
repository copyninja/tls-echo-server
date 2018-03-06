#ifndef __OPENSSL_SERVERLIB_H__
#define __OPENSSL_SERVERLIB_H__

#include <openssl/ssl.h>
#include <openssl/srp.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdbool.h>
#include <assert.h>

#include <sys/select.h>
#include <sys/types.h>

#define CERT_FILE "cert.pem"
#define PRIVKEY_FILE "privkey.pem"
#define BUFLEN 4096
#define SSL_OK 1

void initOpenSSL();
void sslCleanup();
int HandleMessage(SSL*);
int SSL_echo_content(SSL *, const char *, int );
int sslWait(SSL*, int);
int sslHandShake(SSL *);

#endif
