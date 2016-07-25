EXT_SRC = strext.c trie.c json.c hash.c murmur3.c reallocarray.c list.c
AE_SRC = ae.c zmalloc.c anet.c
HTTP_SRC = http_parser.c
SERVER_SRC = main.c server.c
SRC = $(EXT_SRC) $(AE_SRC) $(HTTP_SRC) $(SERVER_SRC)

BIN = ../aehttpd

ifneq ("$(DEBUG)", "")
CFLAGS = -DDEBUG -g
else
CFLAGS = 
endif

LDFLAGS = -lpthread -lz

all:
	gcc ${SRC} -o ${BIN} ${CFLAGS} ${LDFLAGS} 

clean:
	rm ./*.o $(BIN)
