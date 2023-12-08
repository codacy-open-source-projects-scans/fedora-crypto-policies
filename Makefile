VERSION=$(shell git log -1|grep commit|cut -f 2 -d ' '|head -c 7)
DIR?=/usr/share/crypto-policies
BINDIR?=/usr/bin
MANDIR?=/usr/share/man
CONFDIR?=/etc/crypto-policies
DESTDIR?=
MAN7PAGES=crypto-policies.7
MAN8PAGES=update-crypto-policies.8 fips-finish-install.8 fips-mode-setup.8
SCRIPTS=update-crypto-policies fips-finish-install fips-mode-setup
NUM_PROCS = $$(getconf _NPROCESSORS_ONLN)
PYVERSION = -3
DIFFTOOL?=meld
ASCIIDOC?=asciidoc
ifneq ("$(wildcard /usr/lib/python*/*/asciidoc/resources/docbook-xsl/manpage.xsl)","")
MANPAGEXSL?=$(wildcard /usr/lib/python*/*/asciidoc/resources/docbook-xsl/manpage.xsl)
else
MANPAGEXSL?=/usr/share/asciidoc/docbook-xsl/manpage.xsl
endif

all: build

build: $(MAN7PAGES) $(MAN8PAGES)
	mkdir -p output
	python/build-crypto-policies.py --reloadcmds policies output

install: $(MANPAGES)
	mkdir -p $(DESTDIR)$(MANDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man7
	mkdir -p $(DESTDIR)$(MANDIR)/man8
	mkdir -p $(DESTDIR)$(BINDIR)
	install -p -m 644 $(MAN7PAGES) $(DESTDIR)$(MANDIR)/man7
	install -p -m 644 $(MAN8PAGES) $(DESTDIR)$(MANDIR)/man8
	install -p -m 755 $(SCRIPTS) $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(DIR)/
	install -p -m 644 default-config $(DESTDIR)$(DIR)
	install -p -m 644 output/reload-cmds.sh $(DESTDIR)$(DIR)
	for f in $$(find output -name '*.txt') ; do d=$$(dirname $$f | cut -f 2- -d '/')  ; install -p -m 644 -D -t $(DESTDIR)$(DIR)/$$d $$f ; done
	for f in $$(find policies -name '*.p*') ; do d=$$(dirname $$f)  ; install -p -m 644 -D -t $(DESTDIR)$(DIR)/$$d $$f ; done
	for f in $$(find python -name '*.py') ; do d=$$(dirname $$f) ; install -p -m 644 -D -t $(DESTDIR)$(DIR)/$$d $$f ; done
	chmod 755 $(DESTDIR)$(DIR)/python/update-crypto-policies.py
	chmod 755 $(DESTDIR)$(DIR)/python/build-crypto-policies.py

runflake8:
	@find -name '*.py' | grep -v krb5check | xargs flake8 --config .flake8

runpylint:
	PYTHONPATH=. pylint$(PYVERSION) --rcfile=pylintrc python
	PYTHONPATH=. pylint$(PYVERSION) --rcfile=pylintrc tests
	@echo "[ OK ]"

runcodespell:
	codespell -L gost,anull,bund -S .git,./tests/krb5check/*,*.7,*.8

check:
	python/build-crypto-policies.py --strict --test --flat policies tests/outputs
	python/build-crypto-policies.py --strict --policy FIPS:OSPP --test --flat policies tests/outputs
	python/build-crypto-policies.py --strict --policy FIPS:ECDHE-ONLY --test --flat policies tests/outputs
	python/build-crypto-policies.py --strict --policy FIPS:NO-ENFORCE-EMS --test --flat policies tests/outputs
	python/build-crypto-policies.py --strict --policy DEFAULT:GOST --test --flat policies tests/outputs
	python/build-crypto-policies.py --strict --policy GOST-ONLY --test --flat policies tests/outputs
	python/build-crypto-policies.py --strict --policy LEGACY:AD-SUPPORT --test --flat policies tests/outputs
	python/build-crypto-policies.py --strict --policy DEFAULT:FEDORA32 --test --flat policies tests/outputs
	python/build-crypto-policies.py --strict --policy DEFAULT:TEST-PQ --test --flat policies tests/outputs
	diff policies/DEFAULT.pol policies/FEDORA38.pol
	tests/openssl.pl
	tests/gnutls.pl
	tests/nss.py
	tests/java.pl
	tests/krb5.py
	top_srcdir=. tests/update-crypto-policies.sh

# Alternative, equivalent ways to write the same policies
check-alternatives: check
	@rm -rf output/alt
	@mkdir -p output
	cp -r tests/outputs output/alt
	python/build-crypto-policies.py --test --flat tests/alternative-policies output/alt
	python/build-crypto-policies.py --policy FIPS:OSPP --test --flat tests/alternative-policies output/alt
	python/build-crypto-policies.py --policy FIPS:ECDHE-ONLY --test --flat tests/alternative-policies output/alt
	python/build-crypto-policies.py --policy FIPS:NO-ENFORCE-EMS --test --flat tests/alternative-policies output/alt
	python/build-crypto-policies.py --policy GOST-ONLY --test --flat tests/alternative-policies output/alt
	python/build-crypto-policies.py --policy LEGACY:AD-SUPPORT --test --flat tests/alternative-policies output/alt
	python/build-crypto-policies.py --policy DEFAULT:GOST --test --flat tests/alternative-policies output/alt
	python/build-crypto-policies.py --policy DEFAULT:FEDORA32 --test --flat tests/alternative-policies output/alt
	python/build-crypto-policies.py --policy DEFAULT:TEST-PQ --test --flat tests/alternative-policies output/alt
	@rm -rf output/alt

doctest:
	@python3 -Werror -m pytest -vv --doctest-modules python/

unittest:
	@python3 -Werror -m pytest -vv tests/unit/

covtest: #doctest unittest
	@# FIXME: only covers python/cryptopolicies/ files so far
	@# NOTE: doesn't grasp ternaries and short-circuiting operators
	# Don't trust coverage testing
	coverage run --source python/cryptopolicies/ --branch -m pytest -vv --doctest-modules python/ &>/dev/null
	coverage run --append --source python/cryptopolicies/ --branch -m pytest -vv tests/unit/ &>/dev/null
	coverage report --fail-under=100

test: doctest unittest check check-alternatives covtest runcodespell runflake8 runpylint

reset-outputs:
	@rm -rf tests/outputs/*
	@echo "Outputs were reset. Run make check to re-generate, and commit the output."

diff-outputs:
	@rm -rf output/current
	@mkdir -p output/current
	python/build-crypto-policies.py --test --flat policies output/current || true
	python/build-crypto-policies.py --policy FIPS:OSPP --test --flat policies output/current || true
	python/build-crypto-policies.py --policy FIPS:ECDHE-ONLY --test --flat policies output/current || true
	python/build-crypto-policies.py --policy FIPS:NO-ENFORCE-EMS --test --flat policies output/current || true
	python/build-crypto-policies.py --policy DEFAULT:GOST --test --flat policies output/current || true
	$(DIFFTOOL) tests/outputs output/current

clean:
	rm -f $(MAN7PAGES) $(MAN8PAGES) *.?.xml
	rm -rf output

%: %.txt
	$(ASCIIDOC) -v -d manpage -b docbook $<
	xsltproc --nonet -o $@ ${MANPAGEXSL} $@.xml

dist:
	rm -rf crypto-policies && git clone . crypto-policies && rm -rf crypto-policies/.git/ && tar -czf crypto-policies-git$(VERSION).tar.gz crypto-policies && rm -rf crypto-policies

test-install:
	current_policy="$$(update-crypto-policies --show)" ; \
	if [ -z "$$current_policy" ] ; then exit 1; fi ; \
	test_policy=LEGACY ; \
	if [ "$$current_policy" = LEGACY ] ; then test_policy=DEFAULT ; fi ; \
	update-crypto-policies --set $$test_policy || exit $$? ; \
	grep -q $$test_policy $(CONFDIR)/config || exit $$? ; \
	ls -l $(CONFDIR)/back-ends/ | grep -q $$current_policy && exit 2 ; \
	ls -l $(CONFDIR)/back-ends/ | grep -q $$test_policy || exit $$? ; \
	update-crypto-policies --is-applied | grep -q "is applied" || exit $$? ; \
	update-crypto-policies --set $$current_policy || exit $$? ; \
	ls -l $(CONFDIR)/back-ends/ | grep -q $$test_policy && exit 3 ; \
	ls -l $(CONFDIR)/back-ends/ | grep -q $$current_policy || exit $$? ; \
	update-crypto-policies --is-applied | grep -q "is applied" || exit $$?

test-fips-setup:
	CONFDIR=$(CONFDIR) ./tests/test-fips-setup.sh
