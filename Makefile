init:
	pip install pipenv
	pipenv install
	curl -u $vt_key > secret_dev.py

test:
	pipenv run py.test tests
