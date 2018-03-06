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

void openssl_init() {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
}

int sslWait(SSL *ssl, int res) {
  int err = SSL_get_error(ssl, res);
  bool doread;
  switch (err) {
  case SSL_ERROR_WANT_READ:
    doread = true;
    break;
  case SSL_ERROR_WANT_WRITE:
  case SSL_ERROR_WANT_CONNECT:
    doread = false;
    break;
  default:
    return res;
  }

  int fd = SSL_get_fd(ssl);
  fd_set fds;
  FD_ZERO(&fds); FD_SET(fd, &fds);
  if (doread)
    res = select(fd+1, &fds, NULL, NULL, NULL);
  else
    res = select(fd+1, NULL, &fds, NULL, NULL);
  assert(res == 1);
  assert(FD_ISSET(fd, &fds));
  return SSL_OK;
}
int do_handshake(SSL *ssl) {
  while(true) {
    int res = SSL_accept(ssl);
    if (res > 0)
      return res;
    else {
      res = sslWait(ssl, res);
      if (res < 0) return res;
    }
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

int HandleMessage(SSL *ssl) {
  int fd = SSL_get_fd(ssl);
  fd_set fds;
  FD_ZERO(&fds); FD_SET(fd, &fds);

  int bytes_read = 0;
  bool readBlocked = false;
  int err = 0;
  int result = select(fd+1, &fds, NULL, NULL, NULL);

  char buf[BUFLEN];
  if (result < 0)
    return result;
  if (result > 0) {
    if(FD_ISSET(fd, &fds)) {
      do {
        bytes_read = SSL_read(ssl, buf, BUFLEN);
        err = SSL_get_error(ssl, bytes_read);
        switch(err) {
        case SSL_ERROR_NONE:
          result = SSL_echo_content(ssl, buf, bytes_read);
          if (result < 0)
            return result;
          break;
        case SSL_ERROR_ZERO_RETURN:
          /* Connection closed by  */
          return err;
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
          readBlocked = true;
          break;
        default:
          return -1;
        }
      } while(SSL_pending(ssl) && !readBlocked);
    }
  }
  return result;
}

void sslCleanup() {
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  EVP_cleanup();
}

int main(int argc, char *argv[]) {
  openssl_init();
  const SSL_METHOD *method = SSLv23_server_method();

  SSL_CTX *ctx = SSL_CTX_new(method);
  CHECK(ctx != NULL);

  CHECK(SSL_CTX_set_srp_username_callback(ctx, srpCallback) == SSL_OK);

  char port[25];
  sprintf(port, "%d", PORT);
  BIO *server = BIO_new_accept(port);
  CHECK(server != NULL);
  CHECK(BIO_set_bind_mode(server, BIO_BIND_REUSEADDR) == SSL_OK);
  BIO_set_nbio(server, 1);

  /* First accept as listen */
  int ret = BIO_do_accept(server);
  if (ret <= 0) {
    fprintf(stderr, "BIO_do_accept failed: %d\n", ret);
  } else {
    for (;;) {
      if (BIO_do_accept(server) <= 0) {
        if (errno != EINTR) {
          fprintf(stderr, "accept failed\n");
          ERR_print_errors_fp(stderr);
        }
        break;
      }

      /* Get the connection from bio */
      BIO *bio = BIO_pop(server);
      CHECK(bio != NULL);

      if (fork() == 0) {
        BIO_set_close(server, BIO_NOCLOSE);
        BIO_free(server);

        SSL *ssl = SSL_new(ctx);
        SSL_set_bio(ssl, bio, bio);
        SSL_set_accept_state(ssl);

        while(true) {
          int res = do_handshake(ssl);
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

      waitpid(0, NULL, WNOHANG);
      usleep(100000);
    }
  }

  BIO_free(server);
 cleanup:
  if (srpData != NULL) SRP_VBASE_free(srpData);
  SSL_CTX_free(ctx);
  sslCleanup();
}
