SRC = $(wildcard src/*.c)
SSL ?= none

CFLAGS = -Wall -ggdb
ifneq (, $(findstring gnutls,$(SSL)))
LDFLAGS = -lgnutls
filter_files = src/openssl_main.c src/server.c src/openssl_srp.c
SRCS = $(filter-out $(filter_files), $(SRC))
endif

ifneq (, $(findstring openssl,$(SSL)))
LDFLAGS = -lssl -lcrypto
filter_files =  src/gnutls_main.c src/server.c src/openssl_srp.c
SRCS = $(filter-out $(filter_files), $(SRC))
endif

ifneq (, $(findstring none,$(SSL)))
LDFLAGS=
filter_files = src/openssl_main.c src/gnutls_main.c src/openssl_srp.c src/openssl_serverlib.c
SRCS = $(filter-out $(filter_files), $(SRC))
endif

ifneq (, $(findstring openssl-srp, $(SSL)))
LDFLAGS=-lssl -lcrypto
filter_files = src/openssl_main.c src/server.c src/gnutls_main.c
SRCS = $(filter-out $(filter_files), $(SRC))
endif

OBJS = $(patsubst src/%.o, %.o, $(SRCS:.c=.o))

BINARY = server

VPATH = src

.SUFFIXES:
.SUFFIXES: .o.c

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o .obj/$@

$(BINARY): $(OBJS)
		$(CC) -o $(BINARY) $(patsubst %.o, .obj/%.o, $(OBJS)) $(LDFLAGS)

%.pem:
	openssl req -x509 -newkey rsa:4096 -keyout privkey.pem -out cert.pem -days 365 -nodes

run: $(BINARY) privkey.pem cert.pem
	./$(BINARY)
