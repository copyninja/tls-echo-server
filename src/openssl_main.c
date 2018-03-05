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

#define BUFLEN 2048
#define CERT_FILE "cert.pem"
#define PRIVKEY_FILE "privkey.pem"

#define handle_ssl_error(msg) \
  do { perror(msg); ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); } while(0)

void init_openssl() {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

void cleanup() {
  EVP_cleanup();
}

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



int SSL_echo_content(SSL *ssl, char *request, int length) {
  char bye[] = "bye\n";
  if (strstr((const char*)request, "quit") != NULL) {
    SSL_write(ssl, bye, 4);
    return -10;
  }

  return SSL_write(ssl, request, length);
}

int HandleMessages(fd_set *fdlist, int *connfd, SSL *ssl) {
  fd_set testfd = *fdlist;
  char buffer[BUFLEN] = {'\0'};

  struct timeval timeout;

  timeout.tv_sec = 0;
  timeout.tv_usec = 0;

  int result = select(FD_SETSIZE, &testfd, NULL, NULL, &timeout);
  int read_blocked = 0;
  int bytes_read = 0;
  int ssl_error = 0;
  int rv = 0;

  if (result < 0)
    handle_error("select");
  if (result > 0) {
    if (FD_ISSET(*connfd, &testfd)) {
      do {
        read_blocked = 0;
        bytes_read = SSL_read(ssl, buffer, BUFLEN);
        switch(ssl_error = SSL_get_error(ssl, bytes_read)) {
        case SSL_ERROR_NONE:
          /* Handle buffer array */
            rv = SSL_echo_content(ssl, buffer, bytes_read);
            if (rv < 0)
              return rv;
            break;
        case SSL_ERROR_ZERO_RETURN:
          /* Connection closed by client */
          return -1;
        case SSL_ERROR_WANT_READ:
          read_blocked = 1;
          break;
        case SSL_ERROR_WANT_WRITE:
          read_blocked = 1;
          break;
        case SSL_ERROR_SYSCALL:
          return -1;
        default:
          return -1;
        }
      } while(SSL_pending(ssl) && !read_blocked);
    }
  }
  return 0;
}

int main(void) {
  Server s = setup_socket();
  int connfd, flag=1;
  SSL_CTX *ctx;

  init_openssl();
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
        /* Child starts */

        /* Close sockfd we don't need it */
        close(s.sockfd);
        socket_nonblocking(&connfd);

        /* Disable Nagle's algorithm */
        disable_nagles_algo(&connfd);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, connfd);

        if (SSL_accept(ssl) < 0) {
          close(connfd);
          SSL_free(ssl);
          fprintf(stderr, "Failed to do the handshake\n");
          goto cleanup_area;
        }


        /* File descriptor set manipulation */
        FD_ZERO(&fdlist);
        FD_SET(connfd, &fdlist);
        for (;;){
        /* Keep processing  */
          rv = HandleMessages(&fdlist, &connfd, ssl);
          if (rv < 0) {
            SSL_shutdown(ssl);
            close(connfd);
            printf("Calling SSL_free to clear SSL session\n");
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
  cleanup();
}
