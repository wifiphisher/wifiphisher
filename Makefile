.PHONY: docs
init:
	pip install pipenv --upgrade
	pipenv install --dev --skip-lock
test:
	tox

docs:
	cd docs && make html
	@echo "\033[95m\n\nBuild successful!"
