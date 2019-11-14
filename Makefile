build:
	gcc -fPIC -shared -o libnss_curl.so.2 -Wl,-soname,libnss_curl.so.2 nss_curl_conf.c cache.c curl.c json.c shadow.c passwd.c group.c -lcurl -ljansson -lm -lcrypto -lssl
#	gcc -ggdb -o libnss_curl-test json.c cache.c nss_curl_conf.c shadow.c passwd.c group.c curl.c main.c -lcurl -ljansson -lm -lcrypto -lssl

clean:
	rm -rf *.o
	rm -rf libnss_curl.so.2
#	rm -rf libnss_curl-test
install:
	install -m 640 libnss_curl.so.2 /lib/x86_64-linux-gnu
	install -m 640 nss_curl.conf /etc

