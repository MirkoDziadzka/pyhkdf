

all:
	$(MAKE) venv
	$(MAKE) test

venv:
	virtualenv venv
	(. venv/bin/activate && pip install -r requirements.txt)

test:
	(. venv/bin/activate && python -m unittest discover)

clean:
	rm -rf venv *.pyc
