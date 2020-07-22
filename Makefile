#!/usr/bin/make
PYTHON := /usr/bin/python3
export PYTHONPATH := hooks

CHARM_STORE_URL := cs:~nrpe-charmers/nrpe
REPO := git+ssh://git.launchpad.net/nrpe-charm

SHELL := /bin/bash
export SHELLOPTS:=errexit:pipefail


virtualenv:
	virtualenv -p $(PYTHON) .venv
	.venv/bin/pip install flake8 nose mock six

lint: virtualenv
	.venv/bin/flake8 --exclude hooks/charmhelpers hooks tests/10-tests
	@charm proof

submodules:
	@echo "Cloning submodules"
	@git submodule update --init --recursive

test:
	@echo Starting Amulet tests...
	# coreycb note: The -v should only be temporary until Amulet sends
	# raise_status() messages to stderr:
	#   https://bugs.launchpad.net/amulet/+bug/1320357
	@juju test -v -p AMULET_HTTP_PROXY --timeout 900 --upload-tools \
        00-setup 10-tests

check-status:
	@if [ -n "`git status --porcelain`" ]; then \
	    echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'; \
	    echo '!!! There are uncommitted changes !!!'; \
	    echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'; \
	    false; \
	fi
	git clean -fdx

publish-stable: check-status
	export rev=`charm push . $(CHARM_STORE_URL) 2>&1 \
                | tee /dev/tty | grep url: | cut -f 2 -d ' '` \
	&& git tag -f -m "$$rev" `echo $$rev | tr -s '~:/' -` \
	&& git push --tags $(REPO) \
	&& charm release -c stable $$rev

publish-candidate: check-status
	export rev=`charm push . $(CHARM_STORE_URL) 2>&1 \
                | tee /dev/tty | grep url: | cut -f 2 -d ' '` \
	&& git tag -f -m "$$rev" `echo $$rev | tr -s '~:/' -` \
	&& git push --tags $(REPO) \
	&& charm release -c candidate $$rev
