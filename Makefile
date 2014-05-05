PROJECT = callaloo_web
OPTIMIZE = -O3
WARN = -Wall -Wextra -pedantic
CFLAGS += -std=c99 -g ${WARN} ${OPTIMIZE}
LDFLAGS += -lmosquitto

all: ${PROJECT}

OBJS=

${PROJECT}: main.c ${OBJS}
	${CC} -o $@ main.c ${OBJS} ${LDFLAGS}

clean:
	rm -f ${PROJECT} test_${PROJECT} *.o *.core
