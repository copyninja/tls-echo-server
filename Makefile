SRC = $(wildcard src/*.c)
SSL ?= openssl

CFLAGS = -Wall -ggdb
ifeq (, $(findstring gnutls,$(SSL)))
LDFLAGS = -lssl -lcrypto
SRCS = $(filter-out %/gnutls_main.c, $(SRC))
else
LDFLAGS = -lgnutls
SRCS = $(filter-out %/openssl_main.c, $(SRC))
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
