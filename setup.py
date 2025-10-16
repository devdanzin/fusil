#!/usr/bin/env python

# Todo list to prepare a release:
#  - hg in  # check that there is no incoming changes
#  - run: ./pyflakes.sh
#  - run: ./test_doc.py
#  - run: sudo bash -c "PYTHONPATH=$PWD ./fuzzers/fusil-gettext"
#  - edit fusil/version.py: check/set version
#  - edit ChangeLog: set release date
#  - hg ci
#  - hg tag fusil-x.y
#  - hg push
#  - ./setup.py sdist register upload
#  - upload the tarball to Python Package Index
#  - update the website home page (url, md5 and news)
#
# After the release:
#  - edit fusil/version.py: set version to n+1
#  - edit ChangeLog: add a new empty section for version n+1
#  - hg ci
#  - hg push

from importlib.machinery import SourceFileLoader
from os import path
from sys import argv
from glob import glob

CLASSIFIERS = [
    'Intended Audience :: Developers',
    'Development Status :: 5 - Production/Stable',
    'Environment :: Console',
    'License :: OSI Approved :: GNU General Public License (GPL)',
    'Operating System :: OS Independent',
    'Natural Language :: English',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
]

MODULES = (
    "fusil",
    "fusil.linux",
    "fusil.mas",
    "fusil.network",
    "fusil.process",
    "fusil.python",
    "fusil.python.jit",
    "fusil.python.samples",
)

SCRIPTS = glob("fuzzers/fusil-*")

def main():
    if "--setuptools" in argv:
        argv.remove("--setuptools")
        from setuptools import setup
        use_setuptools = True
    else:
        from distutils.core import setup
        use_setuptools = False

    fusil = SourceFileLoader("version", path.join("fusil", "version.py")).load_module()
    PACKAGES = {}
    for name in MODULES:
        PACKAGES[name] = name.replace(".", "/")

    with open('README.rst') as fp:
        long_description = fp.read()
    with open('ChangeLog') as fp:
        long_description += fp.read()

    install_options = {
        "name": fusil.PACKAGE,
        "version": fusil.VERSION,
        "url": fusil.WEBSITE,
        "download_url": fusil.WEBSITE,
        "author": "Victor Stinner",
        "description": "Fuzzing framework",
        "long_description": long_description,
        "classifiers": CLASSIFIERS,
        "license": fusil.LICENSE,
        "packages": list(PACKAGES.keys()),
        "package_dir": PACKAGES,
        "scripts": SCRIPTS,
    }

    if use_setuptools:
        install_options["install_requires"] = ["python-ptrace>=0.7"]
    setup(**install_options)

if __name__ == "__main__":
    main()

