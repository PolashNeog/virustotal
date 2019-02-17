init:
	pip install pipenv
	pipenv install


test:
	pipenv run py.test_virustotal tests
