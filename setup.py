
import pip
import subprocess


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

def requirements():
    return [str(ir.req) for ir in pip.req.parse_requirements('requirements.txt')]
    
def get_version():
    try:
        # pip-installed packages can get the version from the 'version.txt'
        # file, since it is included in the package MANIFEST.
        with open('version.txt', 'r') as f:
            return f.read().strip()
    except IOError:
        # since 'version.txt' is .gitignored, running setup.py (install|develop)
        # from a git repo requires a bit of bootstrapping. in this case, we use
        # the raw .git tag as the version.
        version = "0.0"
        revision = subprocess.check_output(["git", "rev-list", "HEAD", "--count"])
        sha = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"])
        return '-'.join((version, revision, sha))

readme = open('README.rst').read()

setup(
    name='pyhkdf',
    version=get_version(),
    description=("pyhkdf - a straight forward implementation of RFC 5869"
        "HMAC-based Key Derivation Function (HKDF)"),
    long_description=readme,
    author="Mirko Dziadzka",
    author_email="mirko.dziadzka@gmail.com",
    url="https://github.com/MirkoDziadzka/pyhkdf",
    package_dir = {'': 'src'},
    py_modules = ['hkdf'],
    install_requires=requirements(),
    keywords='HKDF',
)

