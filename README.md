# go-sasl
Go wrapper for Cyrus SASL. 

## About
The idea for this project came from (github.com/cloudera/python-sasl), a wrapper for Cyrus SASL written in C++ for use with python. This project aims to do something similar in cgo. 

## Building/Testing
```bash
go get gopkg.in/freddierice/go-sasl.v4
go test
```
To build this project you must have libsasl2 installed.
On Debian: 
```bash
sudo apt-get install libsasl2-dev
```

On Redhat:
```bash
sudo yum install cyrus-sasl-devel.x86_64
```
