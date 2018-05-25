init:
	pip install pipenv --upgrade
	pipenv install --dev --skip-lock
test:
	pytest
coverage:
	pytest --cov=drftoolbox --cov-config=.coveragerc tests && coverage combine --rcfile=.coveragerc
lint:
	pylint drftoolbox
