dev:
	pipenv install --dev
	pipenv shell

deps:
	python3 -m pip install -r requirements.dev.txt

lint:
	pylint poison.py
