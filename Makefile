

pam_telegram_2fa.o: pam_telegram_2fa.c
	gcc -fPIC -lcurl -fno-stack-protector -c pam_telegram_2fa.c

install: pam_telegram_2fa.o
	ld -lcurl -x --shared -o /lib64/security/pam_telegram_2fa.so pam_telegram_2fa.o

uninstall:
	rm -f /lib64/security/pam_telegram_2fa.so
	@echo -e "\n\n      Remove any entry related to this module in /etc/pam.d/ files,\n      otherwise you're not going to be able to login.\n\n"
debug:
	gcc -E -fPIC -lcurl -fno-stack-protector -c pam_telegram_2fa.c
clean:
	rm -rf *.o
