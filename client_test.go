package sasl

import "testing"

// TestNewAndFree tests if a simple test and free functions.
func TestNewAndFree(t *testing.T) {
	cl := NewTestClient(t)
	FreeTest(t, cl)

	cl = NewDefaultClient(t)
	FreeTest(t, cl)
}

// NewDefaultClient creates a new client with a default configuration.
func NewDefaultClient(t *testing.T) *Client {
	cl, err := NewClient("service", "hostname", nil)
	if err != nil {
		t.Fatalf("could not create default client")
	}

	return cl
}

// NewTestClient creates a new client for easy testing.
func NewTestClient(t *testing.T) *Client {
	conf := &Config{
		Username: "user",
		Password: "pass",
	}

	cl, err := NewClient("service", "hostname", conf)
	if err != nil {
		t.Fatalf("could not create client\n%v", err)
	}

	return cl
}

// FreeTest frees the client and determines whether or not it was successful.
func FreeTest(t *testing.T, cl *Client) {
	panicked := false
	if PanickedDuringFree(cl, &panicked); panicked {
		t.Errorf("panic while freeing an uninitialized client")
	}
}

// PanickedDuringFree is a test that determines whether cl panics during
// a free.
func PanickedDuringFree(cl *Client, panickedPtr *bool) {
	defer func() {
		if r := recover(); r != nil {
			*panickedPtr = true
		}
	}()
	cl.Free()
}

// TestUninitializedFree attempts to free a an uninitialized client.
func TestUninitializedFree(t *testing.T) {
	cl := &Client{}
	FreeTest(t, cl)
}

// TestDoubleFree attempts to free a client twice after it was initialized.
func TestDoubleFree(t *testing.T) {
	cl := NewTestClient(t)
	FreeTest(t, cl)
	FreeTest(t, cl)
}
