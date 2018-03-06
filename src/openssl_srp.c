#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/srp.h>
#include <openssl/ssl.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "server_lib.h"
#include "openssl_serverlib.h"

#define CHECK(e) ((e) ? (void)(0):onError(#e, __FILE__, __LINE__, true))
#define SSL_OK 1
#define BUFLEN 4096

const static char *username = "vasudev";
const static char *password = "kamath";
const static char *srpgroup = "1536";

static SRP_VBASE *srpData = NULL;

void onError(const char *s, const char *file, int line, bool doabort) {
  fprintf(stderr, "'%s' failed: %s:%d\n", s, file, line);
  ERR_print_errors_fp(stderr);
  if (doabort) {
    fprintf(stderr, "Aborting...\n");
    abort();
  }
}

void setupSrpData() {
  assert(srpData == NULL);

  srpData = SRP_VBASE_new(NULL);
  CHECK(srpData != NULL);

  SRP_user_pwd *p = (SRP_user_pwd *)OPENSSL_malloc(sizeof(SRP_user_pwd));
  CHECK(p != NULL);

  SRP_gN *gN = SRP_get_default_gN(srpgroup);
  CHECK(gN != NULL);

  char *srpCheck = SRP_check_known_gN_param(gN->g, gN->N);
  CHECK(srpCheck != NULL);

  BIGNUM *salt = NULL, *verifier = NULL;
  CHECK(SRP_create_verifier_BN(username, password, &salt, &verifier, gN->N,
                               gN->g));

  p->id = OPENSSL_strdup(username);
  p->g = gN->g;
  p->N = gN->N;
  p->s = salt;
  p->v = verifier;
  p->info = NULL;

  sk_SRP_user_pwd_push(srpData->users_pwd, p);
}

int srpCallback(SSL *s, int *ad, void *arg) {
  (void)arg;
  (void)ad;

  /* On first call we are not ready return so caller gets WANT_X509_LOOKUP */
  if(srpData == NULL){
    return -1;
  }

  char *username = SSL_get_srp_username(s);
  CHECK(username != NULL);

  SRP_user_pwd *p = SRP_VBASE_get1_by_user(srpData, username);
  if (p == NULL) {
    fprintf(stderr, "User %s does not exist!\n", username);
    return SSL3_AL_FATAL;
  }

  CHECK(SSL_set_srp_server_param(s, p->N, p->g, p->s, p->v, NULL) == SSL_OK);
  SRP_user_pwd_free(p);

  return SSL_ERROR_NONE;
}


int main(int argc, char *argv[]) {
  initOpenSSL();
  const SSL_METHOD *method = SSLv23_server_method();

  SSL_CTX *ctx = SSL_CTX_new(method);
  CHECK(ctx != NULL);

  CHECK(SSL_CTX_set_srp_username_callback(ctx, srpCallback) == SSL_OK);

  char port[25];
  sprintf(port, "%d", PORT);

  Server s = setup_socket();

  pid_t pid;
  fd_set fdlist;
  int connfd;

  for (;;) {
    SSL *ssl = NULL;
    connfd = accept(s.sockfd, (struct sockaddr*)&s.sa, (socklen_t*)&s.addrlen);

    if (connfd < 0 && errno != EAGAIN){
      perror("accept failed");
      goto cleanup;
    }

    if (connfd > 0) {
      if ((pid = fork()) == 0) {
        close(s.sockfd);
        socket_nonblocking(&connfd);
        disable_nagles_algo(&connfd);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, connfd);
        while(true) {
          int res = sslHandShake(ssl);
          if (res > 0)
            break;
          else if (SSL_get_error(ssl, res) == SSL_ERROR_WANT_X509_LOOKUP) {
            setupSrpData();
          } else {
            fprintf(stderr, "Server handshake failed: %d\n", res);
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            return -1;
          }
        }

        FD_ZERO(&fdlist);
        FD_SET(connfd, &fdlist);

        for (;;) {
          int rv = HandleMessage(ssl);
          if(rv < 0){
            if(rv != SSL_ERROR_ZERO_RETURN) {
              SSL_shutdown(ssl);
            }
            SSL_free(ssl);
            goto cleanup;
          }
          usleep(1000);
        }

      }

      close(connfd);
      if (ssl != NULL)
        SSL_free(ssl);
      waitpid(0, NULL, WNOHANG);
      usleep(100000);
    }
  }

 cleanup:
  if (srpData != NULL) SRP_VBASE_free(srpData);
  SSL_CTX_free(ctx);
  sslCleanup();
}
