import os
from setuptools import setup, find_packages


def read(filename):
    return open(os.path.join(os.path.dirname(__file__), filename)).read()


setup(
    name="async43",
    version="0.0.4",
    description="Asynchronous WHOIS client for Python using asyncio. Supports IPv6 and IP rotation.",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Framework :: AsyncIO",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="whois, asyncio, async, ipv6, networking, parser, python, whois-client",
    author="Nicolas Surribas",
    author_email="nicolas.surribas@gmail.com",
    url="https://github.com/devl00p/async43",
    license="MIT",
    packages=find_packages(exclude=["test", "test.*"]),
    package_dir={"async43": "async43"},
    install_requires=["python-dateutil"],
    tests_require=["pytest"],
    include_package_data=True,
    zip_safe=False,
)
