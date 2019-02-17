init:
	pip install pipenv
	pipenv install

test:
	pipenv run .src/py.test tests