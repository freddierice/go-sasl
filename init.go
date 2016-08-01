package sasl

// #cgo LDFLAGS: -lsasl2
// #include <sasl/sasl.h>
import (
	"C"
)
import "log"

func init() {
	// initialize libsasl
	result := C.sasl_client_init(nil)
	if result != C.SASL_OK {
		log.Fatalf("could not start libsasl2: %v\n", C.sasl_errstring(result, nil, nil))
	}
}
