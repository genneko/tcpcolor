# tcpcolor
Reads a pcap file and outputs packet data with colors.  
I wrote this to learn python.

## Note on getent package
You may encounter the following error during package installation.
```text
    long_description = file('README.rst').read(),

NameError: name 'file' is not defined
```

You can work around this by taking the following process.
```text
$ pip install --no-clean getent
(error)
$ vi venv/build/getent/setup.py
(replace file('README.rst') with open('README.rst').)
$ pip install --no-clean --no-download getent
```
