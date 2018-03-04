#ifndef __SERVER_LIB_H__
#define __SERVER_LIB_H__

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <unistd.h>
#include <fcntl.h>

#define handle_error(msg) \
  do { perror(msg); exit(EXIT_FAILURE); } while(0)

#define PORT 50000

typedef struct {
  int sockfd;
  struct sockaddr_in sa;
  int addrlen;
} Server;

Server setup_socket(void);
int echo_content(int *);
void socket_nonblocking(int *);
void disable_nagles_algo(int *);

#endif /* __SERVER_LIB_H__ */
