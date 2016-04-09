CC = gcc
LIBS = -lcrypto -Wl,--no-as-needed -ldl
CFLAGS = -g -fno-stack-protector -Wall -Wno-pointer-sign -Iutil -Iatm -Ibank -Irouter -I.

UNAME := $(shell uname)
ifeq ($(UNAME),Linux)
CFLAGS += -DLINUX -I/usr/local/ssl/include -L/usr/local/ssl/lib 
endif

all: bin/atm bin/bank bin/router

bin/atm : atm/atm-main.c atm/atm.c util/textprocessing.c util/session.c util/user.c util/helpers.c util/hash_table.c util/list.c

	${CC} ${CFLAGS} atm/atm.c atm/atm-main.c util/textprocessing.c util/session.c util/user.c util/helpers.c util/hash_table.c util/list.c -o bin/atm $(LIBS)

bin/bank : bank/bank-main.c bank/bank.c util/textprocessing.c util/helpers.c util/hash_table.c util/list.c util/session.c util/user.c
	${CC} ${CFLAGS} bank/bank.c bank/bank-main.c util/textprocessing.c util/helpers.c util/hash_table.c util/list.c util/session.c util/user.c -o bin/bank $(LIBS)

bin/router : router/router-main.c router/router.c
	${CC} ${CFLAGS} router/router.c router/router-main.c -o bin/router $(LIBS)

test : util/list.c util/list_example.c util/hash_table.c util/hash_table_example.c
	${CC} ${CFLAGS} util/list.c util/list_example.c -o bin/list-test $(LIBS)
	${CC} ${CFLAGS} util/list.c util/hash_table.c util/hash_table_example.c -o bin/hash-table-test $(LIBS)

clean:
	cd bin && rm -f atm bank router list-test hash-table-test
