package sasl

// #cgo LDFLAGS: -lsasl2
// #cgo CFLAGS: -Wall
// #include <sasl/sasl.h>
import "C"
import (
	"bytes"
	"fmt"
	"unsafe"
)

// getPropString collects a property from a connection as a string.
func getPropString(conn *C.struct_sasl_conn, prop C.int) (string, error) {
	var retStr *C.char
	res := C.sasl_getprop(conn, prop, &retStr)
	if res != C.SASL_OK {
		return "", newError(conn, res, "getPropString")
	}
	return C.GoString(retStr), nil
}

// getPropUint collects a property from a connection as a uint.
func getPropUint(conn *C.struct_sasl_conn, prop C.int) (uint, error) {
	var retInt C.uint
	res := C.sasl_getprop(conn, prop, &retInt)
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

// encodePartial readies the bytes in buf for transit, where the number of
// bytes in the buf is ensured to be less than SASL_MAXOUTBUF.
func encodePartial(conn *C.struct_sasl_conn, buf []byte) (out []byte, err error) {
	var outputStr *C.char
	var outputLen C.uint

	input := C.CString(string(buf))
	inputLen := C.uint(len(buf))

	res := C.sasl_encode(conn, input, inputLen, unsafe.Pointer(&outputStr),
		&outputLen)
	if res != C.SASL_OK {
		return nil, newError(conn, res, "encode")
	}

	out = C.GoBytes(outputStr, C.int(outputLen))
	return out, nil
}

// decodePartial decodes the buf from transit, where the number of
// bytes in the buf is ensured to be less than SASL_MAXOUTBUF.
func decodePartial(conn *C.struct_sasl_conn, buf []byte) (out []byte,
	err error) {
	var outputStr *C.char
	var outputLen C.uint

	input := C.CString(string(buf))
	inputLen := C.uint(len(buf))

	res := C.sasl_decode(conn, input, inputLen, unsafe.Pointer(&outputStr),
		&outputLen)
	if res != C.SASL_OK {
		return nil, newError(conn, res, "encode")
	}

	out = C.GoBytes(outputStr, C.int(outputLen))
	return out, nil
}

// encode encodes the bytes for transit.
func encode(conn *C.struct_sasl_conn, buf []byte) ([]byte, error) {
	return fullCoding(conn, buf, encodePartial)
}

// decode decodes the buf from transit.
func decode(conn *C.struct_sasl_conn, buf []byte) ([]byte, error) {
	return fullCoding(conn, buf, decodePartial)
}

// fullCoding encodes/decodes (depending on the partial function), a buffer for
// the conn connection.
func fullCoding(conn *C.struct_sasl_conn, buf []byte,
	partial func(*C.struct_sasl_conn, []byte) ([]byte, error)) (out []byte, err error) {

	byteBuf := &bytes.Buffer{}
	maxBufUint, err := getMaxOutBuf(conn)
	if err != nil {
		return nil, err
	}

	maxBuf := int(maxBufUint)
	for len(buf) > 0 {
		currLen := len(buf)
		if currLen > maxBuf {
			currLen = maxBuf
		}
		segment := buf[0:currLen]
		buf = buf[currLen:]

		partialOut, err := partial(conn, segment)
		if err != nil {
			return nil, err
		}
		byteBuf.Write(partialOut)
	}

	return byteBuf.Bytes(), nil
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
