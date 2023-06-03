# BiggerMAC
BiggerMAC: Analysis tool to introspect and query Android security policies.

# Build Environment

- Ubuntu 20.04.4 LTS x86_64
- Python 3.11.3

# Build Steps

- Download Python 3.11.3 source tarball and build Python

```sh
wget https://www.python.org/ftp/python/3.11.3/Python-3.11.3.tar.xz
tar xJf Python-3.11.3.tar.xz
cd Python-3.11.3 && mkdir tmp && mkdir usr && cd tmp
# install in the current usr directory
../configure --prefix=$PWD/../usr --exec-prefix=$PWD/../usr --enable-optimizations
make -j$(nproc) # maybe you want to execute `make test`
make install    # installed in Python-3.11.3/usr 
```

- use venv to create virtual python environment

```sh
./externals/Python-3.11.3/usr/bin/python3 -m venv ./venv/   # create a virtual env called `venv` in the foler venv
source venv/bin/activate    # activate this virtual environment
```

- install libraries

```sh
pip install python-magic
```

# Workflow

1. Extract Zip files
2. Parse UPDATE.APP
3. use Android sparse image