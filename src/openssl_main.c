#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/wait.h>
#include <netinet/tcp.h>

#include <unistd.h>
#include <utime.h>
#include <fcntl.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "server_lib.h"
#include "openssl_serverlib.h"

#define CERT_FILE "cert.pem"
#define PRIVKEY_FILE "privkey.pem"

#define handle_ssl_error(msg) \
  do { perror(msg); ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); } while(0)


SSL_CTX* create_context() {
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = SSLv23_server_method();
  ctx = SSL_CTX_new(method);
  if (!ctx)
    handle_ssl_error("Failed to create SSL context");

  return ctx;
}

void configure_context(SSL_CTX *ctx) {
  /* Set the key and cert */
  if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
    handle_ssl_error("Failed to use certificate");
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, PRIVKEY_FILE, SSL_FILETYPE_PEM) <= 0){
    handle_ssl_error("Failed to use private key provided");
  }
}


int main(void) {
  Server s = setup_socket();
  int connfd;
  SSL_CTX *ctx;

  initOpenSSL();
  ctx = create_context();
  configure_context(ctx);

  pid_t pid;
  fd_set fdlist;
  int rv = 0;

  for(;;) {
    SSL *ssl = NULL;
    connfd = accept(s.sockfd, (struct sockaddr*)&s.sa, (socklen_t*)&s.addrlen);
    if (connfd < 0 && errno != EAGAIN)
      handle_error("accept");

    if (connfd > 0) {
      if ((pid = fork()) == 0) {
        /* Close sockfd we don't need it */
        close(s.sockfd);

        /* Noblock */
        socket_nonblocking(&connfd);
        /* Disable Nagle's algorithm */
        disable_nagles_algo(&connfd);


        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, connfd);

        while(true) {
          rv = sslHandShake(ssl);
          if (rv > 0)
            break;
          else {
            fprintf(stderr, "SSL handshake failed: %d\n", rv);
            ERR_print_errors_fp(stderr);
            close(connfd);
            SSL_free(ssl);
            return -1;
          }
        }


        /* File descriptor set manipulation */
        FD_ZERO(&fdlist);
        FD_SET(connfd, &fdlist);
        for (;;){
        /* Keep processing  */
          rv = HandleMessage(ssl);
          if (rv < 0) {
            if (rv != SSL_ERROR_ZERO_RETURN)
              SSL_shutdown(ssl);
            close(connfd);
            SSL_free(ssl);
            goto cleanup_area;
          }

          usleep(1000);
        }
      }


      /* parent continues */
      close(connfd);
      if (ssl != NULL)
        SSL_free(ssl);
      waitpid(0, NULL, WNOHANG);
      usleep(100000);
    }
  }

  close(s.sockfd);
 cleanup_area:
  SSL_CTX_free(ctx);
  sslCleanup();
}
