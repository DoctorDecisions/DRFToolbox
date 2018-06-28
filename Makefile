init:
	pip install pipenv --upgrade
	pipenv install -e .
	pipenv install --dev
test:
	pytest
coverage:
	pytest --cov=drftoolbox --cov-config=.coveragerc tests && coverage combine --rcfile=.coveragerc
lint:
	pylint drftoolbox
clean:
	find . -name '*.pyc' -exec rm {} \;
