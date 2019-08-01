CFLAGS += -Werror -Wall
all: pam_upn2sam.so

clean:
	$(RM) test pam_upn2sam.so *.o

pam_upn2sam.so: src/libpam_upn2sam_from_webservice.c
	$(CC) $(CFLAGS) -fPIC -shared -Xlinker -x -o $@ $< -lcurl

install: pam_upn2sam.so
	/bin/cp pam_upn2sam.so /lib/x86_64-linux-gnu/security


