.PHONY: init build test coverate lint clean tag help
.DEFAULT_GOAL := help


init :  ## install and upgrade project deps
	pip install pipenv --upgrade
	pipenv install --dev -e .
build :  ## install locked project deps
	pip install pipenv
	pipenv sync --dev
test :  ## run the test cases
	pytest
coverage :  ## run the test cases and build a coverage report
	pytest --cov=drftoolbox --cov-config=.coveragerc tests && coverage combine --rcfile=.coveragerc
lint :  ## run pylint
	pylint drftoolbox
clean :  ## remove any existing compiled python files
	find . -name '*.pyc' -exec rm {} \;
tag :
	$(eval VER := $(shell python -c 'from drftoolbox.__version__ import __version__; print(__version__);'))
	$(eval LAST_BUILD := $(shell (git describe --abbrev=0 --tags 2>/dev/null || echo 'vXb0') | cut -d'b' -f 2))
	$(eval BUILD ?= $(shell expr ${LAST_BUILD} + 1))
	git tag -a "v${VER}b${BUILD}" -m'auto commit tag'
	@(grep github.com ~/.ssh/known_hosts || ssh-keyscan -H github.com 2>/dev/null >> ~/.ssh/known_hosts) > /dev/null
	git push origin "v${VER}b${BUILD}"
help :
	@cat $(MAKEFILE_LIST) | grep -e "^[a-zA-Z_\-]*%\? : *.*## *" | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
