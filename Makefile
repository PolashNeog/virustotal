TESTDIR = src/tests

init:
	pip install pipenv
	pipenv install --dev

test:
	pipenv run -- py.test test_virustotal -s -v