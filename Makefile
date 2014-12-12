

all:
	$(MAKE) venv
	$(MAKE) test

venv:
	virtualenv venv
	(. venv/bin/activate && pip install -r requirements.txt)

.PHONY: test
test:
	(. venv/bin/activate && cd src && python -m unittest discover)


clean:
	rm -rf venv *.pyc


