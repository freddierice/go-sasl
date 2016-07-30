package sasl

import (
	"testing"
)

func TestCreateDestroyClient(t *testing.T) {
	c := NewClient()
	c.Free()
}

func TestSetAttributes(t *testing.T) {
	c := NewClient()
	c.SetService("newservice")
	c.Free()
}
