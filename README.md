# BiggerMAC
BiggerMAC: Analysis tool to introspect and query Android security policies.

# Build Environment

- Ubuntu 20.04.4 LTS x86_64
- Python 3.11.3

# Build Steps

- Download Python 3.11.3 source tarball and build Python
- In order to get IPython embed() ability, install libsqlite3-dev

```sh
sudo apt install libsqlite3-dev
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

- install `setools` (depend on selinux project)

```sh
# For C libraries and programs
sudo apt install bison flex gawk gcc gettext make libaudit-dev libbz2-dev libcap-dev libcap-ng-dev libcunit1-dev libglib2.0-dev libpcre2-dev pkgconf systemd xmlto
```

build setools commands

```sh
wget https://github.com/SELinuxProject/selinux/releases/download/3.5/selinux-3.5.tar.gz
tar xzf selinux-3.5.tar.gz
cd selinux-3.5
SELINUX_SRC=$(pwd)/libselinux
SEPOL_SRC=$(pwd)/libsepol
make -C $SEPOL_SRC
make CFLAGS="-O2 -pipe -fPIC -Wall -I${SEPOL_SRC}/include" LDFLAGS="-L${SEPOL_SRC}/src" -C ${SELINUX_SRC}
```

version 3.2 (cf853c1a0c2328ad6c62fb2b2cc55d4926301d6)

```sh
wget https://codeload.github.com/SELinuxProject/selinux/zip/cf853c1a0c2328ad6c62fb2b2cc55d4926301d6
unzip cf853c1a0c2328ad6c62fb2b2cc55d4926301d6
cd selinux-cf853c1a0c2328ad6c62fb2b2cc55d4926301d6b
SELINUX_SRC=$(pwd)/libselinux
SEPOL_SRC=$(pwd)/libsepol
CHECKPOLICY_SRC=$(pwd)/checkpolicy
make -C $SEPOL_SRC
make CFLAGS="-O2 -pipe -fPIC -Wall -I${SEPOL_SRC}/include" LDFLAGS="-L${SEPOL_SRC}/src" -C ${SELINUX_SRC}
make CFLAGS="-O2 -pipe -fPIC -Wall -I${SEPOL_SRC}/include" -C ${CHECKPOLICY_SRC}
LD_LIBRARY_PATH="${SEPOL_SRC}/src:${SELINUX_SRC}/src:${LD_LIBRARY_PATH}" python setup.py build_ext -i
```

setools version 4.4.2

```sh
wget https://github.com/SELinuxProject/setools/releases/download/4.4.2/setools-4.4.2.tar.bz2
tar xjf setools-4.4.2.tar.bz2 && cd setools
pip install Cython
pip install networkx
USERSPACE_SRC=/home/u/BiggerMAC/externals/selinux-3.5/ python setup.py build_ext -i
```

```sh
LD_LIBRARY_PATH=/home/u/BiggerMAC/externals/selinux-3.5/libsepol/src python
```

# Workflow

1. Extract Zip files
2. Parse UPDATE.APP
3. use Android sparse image
4. to emulate the behavior of the Android init process
    - parse all the init.rc files available in the system
    - emulate the behavior of the init process in `boot_system`

.pxi 文件是 Cython 的类型声明文件，用于在 Cython 中定义类型和接口。它通常与 .pyx 文件一起使用，提供对外部代码的类型和接口声明。

.pyx 是一个用于编写 Cython 代码的文件扩展名。Cython 是一个用于将 Python 代码转换为 C/C++ 代码并与原生代码进行混合编程的工具。.pyx 文件包含了 Cython 代码的源代码。