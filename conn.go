package sasl

// #cgo LDFLAGS: -lsasl2
// #cgo CFLAGS: -Wall
// #include <sasl/sasl.h>
// #include <stdio.h>
//
// int getprop_uint(sasl_conn_t *conn, int propnum, unsigned *ret_num) {
//     int ret;
//     unsigned *ret_num_ptr;
//     ret = sasl_getprop(conn, propnum, (const void **)&ret_num_ptr);
//     *ret_num = *ret_num_ptr;
//     return ret;
// }
import "C"
import (
	"fmt"
	"unsafe"
)

// getPropString collects a property from a connection as a string.
func getPropString(conn *C.struct_sasl_conn, prop C.int) (string, error) {
	var retStr *C.char
	p := unsafe.Pointer(retStr)
	res := C.sasl_getprop(conn, prop, &p)
	if res != C.SASL_OK {
		return "", newError(conn, res, "getPropString")
	}
	return C.GoString(retStr), nil
}

// getPropUint collects a property from a connection as a uint.
func getPropUint(conn *C.struct_sasl_conn, prop C.int) (uint, error) {
	retInt := C.uint(1)
	res := C.getprop_uint(conn, prop, &retInt)
	if res != C.SASL_OK {
		return 0, newError(conn, res, "getPropUint")
	}
	return uint(retInt), nil
}

// getUsername collects the SASL_USERNAME property from the connection.
func getUsername(conn *C.struct_sasl_conn) (string, error) {
	return getPropString(conn, C.SASL_USERNAME)
}

// getMaxOutBuf collects the SASL_MAXOUTBUF property from the connection.
func getMaxOutBuf(conn *C.struct_sasl_conn) (uint, error) {
	return getPropUint(conn, C.SASL_MAXOUTBUF)
}

// getSSF collects the SASL_SSF property from the connection.
func getSSF(conn *C.struct_sasl_conn) (uint, error) {
	return getPropUint(conn, C.SASL_SSF)
}

func encode(conn *C.struct_sasl_conn, buf []byte) (out []byte, err error) {
	var outputStr *C.char
	var outputLen C.uint

	input := C.CString(string(buf))
	inputLen := C.uint(len(buf))

	res := C.sasl_encode(conn, input, inputLen, &outputStr,
		&outputLen)
	if res != C.SASL_OK {
		return nil, newError(conn, res, "encode")
	}

	out = C.GoBytes(unsafe.Pointer(outputStr), C.int(outputLen))
	return out, nil
}

func decode(conn *C.struct_sasl_conn, buf []byte) (out []byte,
	err error) {
	var outputStr *C.char
	var outputLen C.uint

	input := C.CString(string(buf))
	inputLen := C.uint(len(buf))

	res := C.sasl_decode(conn, input, inputLen, &outputStr,
		&outputLen)
	if res != C.SASL_OK {
		return nil, newError(conn, res, "decode")
	}

	out = C.GoBytes(unsafe.Pointer(outputStr), C.int(outputLen))
	return out, nil
}

// newError creates a new error from a connection result.
func newError(conn *C.struct_sasl_conn, res C.int, msg string) error {
	var errMsgStr *C.char

	if conn == nil {
		errMsgStr = C.sasl_errstring(res, nil, nil)
	} else {
		errMsgStr = C.sasl_errdetail(conn)
	}

	errMsg := C.GoString(errMsgStr)
	return fmt.Errorf("err in %v: %v\n", msg, errMsg)
}
