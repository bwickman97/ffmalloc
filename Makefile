LIB_NAME=ffmalloc
LIB_SHARED_MT=lib${LIB_NAME}mt.so
LIB_SHARED_ST=lib${LIB_NAME}st.so
LIB_SHARED_INST=lib${LIB_NAME}inst.so
LIB_SHARED_NPMT=lib${LIB_NAME}npmt.so
LIB_SHARED_NPST=lib${LIB_NAME}npst.so
LIB_SHARED_NPINST=lib${LIB_NAME}npinst.so

LIB_OBJS_MT=ffmallocmt.o
LIB_OBJS_ST=ffmallocst.o
LIB_OBJS_INST=ffmallocinst.o
LIB_OBJS_NPMT=ffmallocnpmt.o
LIB_OBJS_NPST=ffmallocnpst.o
LIB_OBJS_NPINST=ffmallocnpinst.o
#LIB_SRCS=${patsubst %.o,%.c,${LIB_OBJS}}

#OBJS=
#SRCS=${patsubst %.o,%.c,${OBJS}}

#CFLAGS=-Wall -Wextra -fPIC -c -g -O3
CFLAGS=-Wall -Wextra -Wno-unknown-pragmas -fPIC -c -g -O3 -DFF_GROWLARGEREALLOC -D_GNU_SOURCE
#CFLAGS=-Wall -Wextra -fPIC -c -O3 -DFF_PROFILE
CC=gcc

all: prefixed noprefix

prefixed: sharedmt sharedst sharedinst

noprefix: sharednpmt sharednpst sharednpinst

sharedmt: ${LIB_SHARED_MT}

sharedst: ${LIB_SHARED_ST}

sharedinst: ${LIB_SHARED_INST}

sharednpmt: ${LIB_SHARED_NPMT}

sharednpst: ${LIB_SHARED_NPST}

sharednpinst: ${LIB_SHARED_NPINST}

${LIB_SHARED_MT}: ${LIB_OBJS_MT}
	${CC} -o $@ -shared -fPIC -pthread $^

${LIB_SHARED_ST}: ${LIB_OBJS_ST}
	${CC} -o $@ -shared -fPIC $^

${LIB_SHARED_INST}: ${LIB_OBJS_INST}
	${CC} -o $@ -shared -fPIC $^

${LIB_SHARED_NPMT}: ${LIB_OBJS_NPMT}
	${CC} -o $@ -shared -fPIC -pthread $^

${LIB_SHARED_NPST}: ${LIB_OBJS_NPST}
	${CC} -o $@ -shared -fPIC $^

${LIB_SHARED_NPINST}: ${LIB_OBJS_NPINST}
	${CC} -o $@ -shared -fPIC $^

${LIB_OBJS_MT}: ffmalloc.c
	${CC} ${CFLAGS} -DUSE_FF_PREFIX ffmalloc.c -o $@

${LIB_OBJS_ST}: ffmalloc.c
	${CC} ${CFLAGS} -DUSE_FF_PREFIX -DFFSINGLE_THREADED ffmalloc.c -o $@

${LIB_OBJS_INST}: ffmalloc.c
	${CC} ${CFLAGS} -DUSE_FF_PREFIX -DFFSINGLE_THREADED -DFF_INSTRUMENTED ffmalloc.c -o $@

${LIB_OBJS_NPMT}: ffmalloc.c
	${CC} ${CFLAGS} ffmalloc.c -o $@

${LIB_OBJS_NPST}: ffmalloc.c
	${CC} ${CFLAGS} -DFFSINGLE_THREADED ffmalloc.c -o $@

${LIB_OBJS_NPINST}: ffmalloc.c
	${CC} ${CFLAGS} -DFFSINGLE_THREADED -DFF_INSTRUMENTED ffmalloc.c -o $@

ffmalloc.c: ffmalloc.h

clean:
	rm *.o
	rm *.so
