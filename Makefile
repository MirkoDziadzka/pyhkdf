

all:
	$(MAKE) venv
	$(MAKE) test

venv:
	virtualenv venv
	(. venv/bin/activate && pip install -r requirements.txt)

.PHONY: test
test:
	(. venv/bin/activate && cd src && python -m unittest discover)

.PHONY: coverage
coverage:
	(cd src && coverage erase && coverage run --source . -m unittest discover && coverage html)


clean:
	rm -rf venv *.pyc


