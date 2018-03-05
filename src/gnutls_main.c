#include "server_lib.h"

#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include <sys/wait.h>
#include <gnutls/gnutls.h>

#define CHECK(x) assert((x)>=0)

#define CERTFILE "cert.pem"
#define KEYFILE "privkey.pem"
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"

#define BUFLEN 2048

int HandleMessage(gnutls_session_t *session, fd_set *fdlist, int *connfd) {
  fd_set testfd = *fdlist;
  char buffer[BUFLEN] = {'\0'};
  int rv = 0;

  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 0;

  int result = select(FD_SETSIZE, &testfd, NULL, NULL, &timeout);
  if (result < 0)
    handle_error("select");

  int bytes_to_read = 0;
  if (result > 0) {
    if (FD_ISSET(*connfd, &testfd)) {
    read:
      /* We have some data to read */
      rv = gnutls_record_recv(*session, buffer, BUFLEN);
      if (rv > 0) {
        if (strstr((const char*)buffer, "quit") != NULL) {
          CHECK(gnutls_record_send(*session, "bye\n", 4));
          return -10;
        }
        CHECK(gnutls_record_send(*session, buffer, rv));
      } else if (rv == 0) {
        printf("\n- Peer has closed the connection\n");
        return -10;
      } else if (rv < 0 && gnutls_error_is_fatal(rv) == 0) {
        fprintf(stderr, "*** WARNING: %s\n", gnutls_strerror(rv));
        return -10;
      } else if (rv < 0) {
        fprintf(stderr, "\n *** Received corrupted "
                "data(%d). Closing connection\n\n", rv);
        return -10;
      }

      bytes_to_read = gnutls_record_check_pending(*session);
      if (bytes_to_read > 0)
        goto read;
    }
  }
  return 0;
}

int main(void) {
  Server s = setup_socket();
  int connfd;

  pid_t pid;
  fd_set fdlist;
  int rv = 0;
  char topbuf[512];

  gnutls_certificate_credentials_t x509_cred;
  gnutls_priority_t priority_cache;
  gnutls_session_t session;

  CHECK(gnutls_global_init());
  CHECK(gnutls_certificate_allocate_credentials(&x509_cred));
  CHECK(gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE,
                                               GNUTLS_X509_FMT_PEM));
  if((rv = gnutls_certificate_set_x509_key_file(x509_cred, CERTFILE, KEYFILE, GNUTLS_X509_FMT_PEM)) < 0) {
    printf("ERROR: %s\n", gnutls_strerror(rv));
    exit(rv);
  }

  CHECK(gnutls_priority_init(&priority_cache, "NORMAL:%SERVER_PRECEDENCE", NULL));

#if GNUTLS_VERSION_NUMBER >= 0x030506
  /* only available since GnuTLS 3.5.6, on previous versions see
   * gnutls_certificate_set_dh_params(). */
  gnutls_certificate_set_known_dh_params(x509_cred, GNUTLS_SEC_PARAM_MEDIUM);
#endif
  for (;;) {
    connfd =
        accept(s.sockfd, (struct sockaddr *)&s.sa, (socklen_t *)&s.addrlen);
    if (connfd < 0 && errno != EAGAIN)
      handle_error("accept");

    if (connfd > 0) {
      CHECK(gnutls_init(&session, GNUTLS_SERVER));
      CHECK(gnutls_priority_set(session, priority_cache));
      CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred));

      gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

      printf("- connection from %s, port %d\n",
             inet_ntop(AF_INET, &s.sa.sin_addr, topbuf, sizeof(topbuf)),
             ntohs(s.sa.sin_port));

      printf("- Handshake was completed\n");

      if ((pid = fork()) == 0) {
        close(s.sockfd);
        socket_nonblocking(&connfd);
        disable_nagles_algo(&connfd);

        gnutls_transport_set_int(session, connfd);
        do {
          rv = gnutls_handshake(session);
        } while (rv < 0 && gnutls_error_is_fatal(rv) == 0);

        if (rv < 0) {
          close(connfd);
          gnutls_deinit(session);
          fprintf(stderr, "*** Handshake has failed (%s)\n\n", gnutls_strerror(rv));
          goto cleanup;
        }

        FD_ZERO(&fdlist);
        FD_SET(connfd, &fdlist);

        for (;;) {
          rv = HandleMessage(&session, &fdlist, &connfd);
          if ( rv < 0) {
            gnutls_bye(session, GNUTLS_SHUT_RDWR);
            close(connfd);
            gnutls_deinit(session);
            goto cleanup;
          }

          usleep(1000);
        }
      }

      close(connfd);
      gnutls_deinit(session);
      waitpid(0, NULL, WNOHANG);
      usleep(100000);
    }
  }

  close(s.sockfd);
  gnutls_deinit(session);

 cleanup:
  gnutls_certificate_free_credentials(x509_cred);
  gnutls_priority_deinit(priority_cache);
  gnutls_global_deinit();

  return 0;
}
