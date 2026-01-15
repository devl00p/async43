install: clean
		pip3 install .

test:
		python -m pytest

clean:
		rm -rf dist/ build/ async43.egg-info/

style:
		pylint async43

release: clean
		python -m build --sdist --wheel
