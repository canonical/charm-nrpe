PYTHON := /usr/bin/python3

ifndef CHARM_BUILD_DIR
	CHARM_BUILD_DIR=/tmp/charm-builds
endif

PROJECTPATH=$(dir $(realpath $(MAKEFILE_LIST)))
METADATA_FILE="metadata.yaml"
CHARM_NAME=$(shell cat ${PROJECTPATH}/${METADATA_FILE} | grep -E '^name:' | awk '{print $$2}')

help:
	@echo "This project supports the following targets"
	@echo ""
	@echo " make help - show this text"
	@echo " make clean - remove unneeded files"
	@echo " make submodules - make sure that the submodules are up-to-date"
	@echo " make build - build the charm"
	@echo " make release - run clean, submodules and build targets"
	@echo " make lint - run flake8 and black"
	@echo " make proof - run charm proof"
	@echo " make unittests - run the tests defined in the unittest subdirectory"
	@echo " make functional - run the tests defined in the functional subdirectory"
	@echo " make test - run lint, proof, unittests and functional targets"
	@echo ""

clean:
	@echo "Cleaning files"
	@if [ -d .tox ] ; then rm -r .tox ; fi
	@if [ -d .pytest_cache ] ; then rm -r .pytest_cache ; fi
	@if [ -d .idea ] ; then rm -r .idea ; fi
	@if [ -d .coverage ] ; then rm -r .coverage ; fi
	@if [ -d report ] ; then rm -r report ; fi
	@if [ -f revision ] ; then rm revision ; fi
	@find . -iname __pycache__ -exec rm -r {} +
	@find . -type f -name "*.py[cod]" -delete
	@find . -type f -name "*$py.class" -delete
	@find . -type f -name "*.log" -delete
	@find . -type f -name "*.swp" -delete
	@find . -type f -name ".unit-state.db" -delete
	@find . -type f -name ".unit-state.db" -delete
	@echo "Cleaning existing build"
	@rm -rf ${CHARM_BUILD_DIR}/${CHARM_NAME}

submodules:
	@echo "Cloning submodules"
	@git submodule update --init --recursive

build:
	@echo "Building charm to base directory ${CHARM_BUILD_DIR}/${CHARM_NAME}"
	@-git describe --tags > ./repo-info
	@mkdir -p ${CHARM_BUILD_DIR}/${CHARM_NAME}
	@cp -r ./* ${CHARM_BUILD_DIR}/${CHARM_NAME}

release: clean submodules build
	@echo "Charm is built at ${CHARM_BUILD_DIR}/${CHARM_NAME}"

lint:
	@echo "Running lint checks"
	@tox -e lint

proof:
	@echo "Running charm proof"
	@charm proof

unittests:
	@echo "There are no unit tests to run"

functional: build
	@echo "Executing functional tests in ${CHARM_BUILD_DIR}"
	@CHARM_BUILD_DIR=${CHARM_BUILD_DIR} tox -e func

test: lint proof unittests functional
	@echo "Charm ${CHARM_NAME} has been tested"

# The targets below don't depend on a file
.PHONY: help submodules clean build release lint proof unittests functional test
