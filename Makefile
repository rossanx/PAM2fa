

pam_telegram_2fa.o: pam_telegram_2fa.c
	gcc -fPIC -lcurl -fno-stack-protector -c pam_telegram_2fa.c

install: pam_telegram_2fa.o
	ld -lcurl -x --shared -o /lib64/security/pam_telegram_2fa.so pam_telegram_2fa.o

debug:
	gcc -E -fPIC -lcurl -fno-stack-protector -c pam_telegram_2fa.c
clean:
	rm -rf *.o
