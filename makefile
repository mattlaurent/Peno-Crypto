CC=gcc
CFLAGS=-I.
DEPS = ccm.h
OBJ = ccm.o main.o aes.o
LIBS = -lm

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

ccm: $(OBJ)
	$(CC) -o  $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean
clean :
	rm ccm $(OBJ)
