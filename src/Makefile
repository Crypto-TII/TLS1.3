client:
	mv TLS1_3.h tls1_3.h || true
	clang++ -O2 client.cpp tls_keys_calc.cpp tls_sockets.cpp tls_cert_chain.cpp tls_client_recv.cpp tls_client_send.cpp tls_tickets.cpp tls_logger.cpp tls_cacerts.cpp core.a -o client

copy-dependencies:
	cp ../../miracl-core/cpp/core.a ./vendor/miracl/
	cp ../../miracl-core/cpp/*.h ./vendor/miracl/includes/
.PHONY: copy-dependencies

clean:
	rm -f client
.PHONY: clean

run: client
	./client tls13.1d.pw
.PHONY: run
