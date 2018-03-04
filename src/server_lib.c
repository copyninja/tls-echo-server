#include "server_lib.h"


Server setup_socket(void) {

  int sd, err;
  sd = socket(AF_INET, SOCK_STREAM, 0);

  /* Set socket re-use */
  int flag = 1;
  err = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));
  if (err != 0)
    handle_error("setsockopt");

  /* Make socket non blocking */
  err = fcntl(sd, F_SETFL, O_ASYNC | O_NONBLOCK);
  if (err != 0)
    handle_error("fcntl");

  struct sockaddr_in sa;
  memset(&sa, '\0', sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(PORT);
  sa.sin_addr.s_addr = INADDR_ANY;

  if (bind(sd, (struct sockaddr*)&sa, sizeof(sa)) != 0)
    handle_error("bind");

  if (listen(sd, 0) != 0)
    handle_error("listen");

  Server s = {.sockfd = sd, .sa = sa, .addrlen = sizeof(struct sockaddr_in)};

  return s;
}

int echo_content(int *connfd) {
  unsigned char buffer[2048];
  int size = recv(*connfd, buffer, sizeof(buffer), 0);
  if (size < 0)
    handle_error("recv");

  if (size > 0) {
    if (strstr((const char*)buffer, "quit") != NULL){
      printf("Closing connection with client\n");
      send(*connfd, "bye\n", 4, 0);
      return -10;
    }

    size = send(*connfd, buffer, size, 0);
    if (size < 0) {
      handle_error("send");
    }
  } else
    printf("WARNING: Failed to recieve data\n");

  return size;
}

void socket_nonblocking(int *connfd) {
  int options = fcntl(*connfd, F_GETFL, 0);
  if (options < 0)
    handle_error("fcntl");

  options |= O_NONBLOCK;
  if (fcntl(*connfd, F_SETFL, options) < 0)
    handle_error("fnctl");
}

void disable_nagles_algo(int *connfd) {
  int flag = 1;
  if (setsockopt(*connfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int)) < 0)
    handle_error("setsockopt");
}
