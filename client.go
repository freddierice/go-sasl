package sasl

// #cgo CFLAGS: -I./saslwrapper
// #cgo LDFLAGS: -lsasl2 -L./saslwrapper -lsaslwrapper
// #include <saslwrapper.h>
import "C"

// Client is the golang representation of a sasl client connection.
type Client struct {
	clientPtr *C.struct_ClientImpl_struct
	freed     bool
}

func NewClient() *Client {
	return &Client{
		clientPtr: C.newClient(),
		freed:     false,
	}
}

func (c *Client) Free() {
	if c.freed {
		return
	}
	C.freeClient(c.clientPtr)
}

func (c *Client) SetService(service string) {
	if c.freed {
		return
	}
	serviceStr := C.CString(service)
	C.setService(c.clientPtr, serviceStr)
}
