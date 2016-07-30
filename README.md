# go-sasl
Go wrapper for Cyrus SASL. 

## About
The idea for this project came from (github.com/cloudera/python-sasl), a wrapper for Cyrus SASL written in C++ for use with python. This project aims to do something similar in pure C code to be used with cgo, then to build a library in go for developers to easily use. 


## Building
To build this project you must have libsasl2 installed.
```bash
(cd saslwrapper && make)
go build
```
