#include "server_lib.h"

#include <errno.h>

int HandleMessage(fd_set *fdlist, int *connfd) {
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 0;

  fd_set testfd = *fdlist;
  int rv = 0;

  int result = select(FD_SETSIZE, &testfd, NULL, NULL, &timeout);
  if (result < 0)
    handle_error("select");

  if (result > 0) {
    if(FD_ISSET(*connfd, &testfd)) {
      /* We have some data */
      return echo_content(connfd);
    }
  }

  return 0;
}

int main(void) {
  Server s = setup_socket();
  int connfd;
  char buffer[512];


  pid_t pid;
  fd_set fdlist;
  int rv = 0;

  for(;;) {
    connfd = accept(s.sockfd, (struct sockaddr*)&s.sa, (socklen_t*)&s.addrlen);
    if (connfd < 0 && errno != EAGAIN)
      handle_error("accept");

    if (connfd > 0) {
      printf("\n- Accepted connection from %s port %d\n",
             inet_ntop(AF_INET, &s.sa.sin_addr, buffer, sizeof(buffer)),
             ntohs(s.sa.sin_port));
      if ((pid = fork()) == 0) {
        /* Child starts processing connection */
        close(s.sockfd);
        socket_nonblocking(&connfd);
        disable_nagles_algo(&connfd);

        FD_ZERO(&fdlist);
        FD_SET(connfd, &fdlist);
        for (;;) {
          rv = HandleMessage(&fdlist, &connfd);
          if (rv < 0) {
            close(connfd);
            exit(EXIT_SUCCESS);
          }

        }
      }

      close(connfd);
    }
  }

  close(s.sockfd);
  return 0;
}
