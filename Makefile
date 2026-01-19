.PHONY: install test clean style release

install: clean
		pip3 install .

test:
		python -m pytest

clean:
		rm -rf dist/ build/ async43.egg-info/

style:
		pylint --rcfile=.pylintrc async43

release: clean
		python -m build --sdist --wheel
