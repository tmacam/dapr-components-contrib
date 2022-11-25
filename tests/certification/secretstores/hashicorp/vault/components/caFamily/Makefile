
TARGETS = certificates/key.pem certificates/cert.pem caPem/hashicorp-vault.yml

all: $(TARGETS)

# Create cert and key lasting 10 years, no password,  no prompt for
# subject details. Also set subjectAltName so we avoid the
# "x509: certificate relies on legacy Common Name field" errors

certificates/key.pem certificates/cert.pem:
	openssl req -x509 -newkey rsa:4096 \
		-keyout key.pem \
		-out cert.pem \
		-sha256 -days 3650 \
		-nodes \
		-addext "subjectAltName = DNS:hashicorp_vault,DNS:localhost,IP:127.0.0.1" \
		-subj "/C=CA/ST=BC/L=Vancouver/O=Dapr Testing/OU=Org/CN=www.dapr.io"
	chmod -v 644 *.pem
		

caPem/hashicorp-vault.yml: caPem/hashicorp-vault.yml.template certificates/cert.pem
	cat caPem/hashicorp-vault.yml.template >  $@ &&\
	sed 's/^/          /' certificates/cert.pem >> $@


clean:
	rm -f -v $(TARGETS)

.PHONY: clean
.PHONY: all