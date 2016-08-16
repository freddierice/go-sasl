package sasl

// #cgo LDFLAGS: -lsasl2
// #cgo CFLAGS: -Wall
// #include <sasl/sasl.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
//
// typedef struct SaslServer_struct {
//     sasl_conn_t *ss_conn;
// } SaslServer;
//
// SaslServer* new_server() {
//     SaslServer *ret = (SaslServer *)malloc(sizeof(SaslServer));
//     memset(ret, 0, sizeof(SaslServer));
//     return ret;
// }
//
import (
	"C"
)
import (
	"log"
	"unsafe"
)

// Server holds the information necesary to keep state within the server
type Server struct {
	// libsaslwrapper
	server        *C.struct_SaslServer_struct
	handshakeDone bool
	ptrs          []unsafe.Pointer
}

// init starts the underlying sasl libraries so that plugins can be in place
// before we create any servers.
func init() {
	result := C.sasl_server_init(nil, C.CString("CyrusSASL"))
	if result != C.SASL_OK {
		log.Fatalf("could not start libsasl2: %v\n", C.sasl_errstring(result, nil, nil))
	}

}

// NewServer creates a server. Both service and host are necesary. Realm will
// will be derived by host in this case.
func NewServer(service, host, realm string) (*Server, error) {
	ss := &Server{}
	ss.server = C.new_server()

	serviceStr := C.CString(service)
	hostStr := C.CString(host)
	realmStr := (*C.char)(unsafe.Pointer(nil))
	if realm != "" {
		realmStr = C.CString(realm)
		ss.addDanglingPtrs(unsafe.Pointer(realmStr))
	}
	ss.addDanglingPtrs(unsafe.Pointer(serviceStr), unsafe.Pointer(hostStr))
	res := C.sasl_server_new(serviceStr, hostStr, realmStr, nil, nil, nil,
		0, unsafe.Pointer(&ss.server.ss_conn))
	if res != C.SASL_OK {
		err := ss.newError(res, "NewServer")
		ss.Free()
		return nil, err
	}

	return ss, nil
}

// ListMech provides a list of mechanisms with which the server can negotiate.
func (ss *Server) ListMech() ([]string, error) {
	var retstr *C.char
	prefixStr := C.CString("")
	sepStr := C.CString(",")
	suffixStr := C.CString("")
	res := C.sasl_listmech(ss.server.ss_conn, nil, prefixStr, sepStr, suffixStr,
		&retstr, nil, nil)
	if res != C.SASL_OK {
		return nil, ss.newError(res, "ListMech")
	}

	return nil, nil
}

// Start initialtes the handshake between the server and client, where mech is
// the agreed upon mechanism and challenge is the first set of bytes sent from
// the client to the server. If done is true, the handshake is complete.
func (ss *Server) Start(mech string, challenge []byte) (response []byte,
	done bool, err error) {

	var responseStr *C.char
	var responseLen C.uint

	challengeStr := C.CString(string(challenge))
	challengeLen := C.uint(len(challenge))
	mechStr := C.CString(mech)

	ss.addDanglingPtrs(unsafe.Pointer(challengeStr), unsafe.Pointer(mechStr))
	res := C.sasl_server_start(ss.server.ss_conn, mechStr, challengeStr,
		challengeLen, &responseStr, &responseLen)
	if res != C.SASL_OK || res != C.SASL_CONTINUE {
		return nil, false, ss.newError(res, "Start")
	} else if res == C.SASL_OK {
		ss.handshakeDone = true
	}

	response = C.GoBytes(responseStr, C.int(responseLen))
	return response, ss.handshakeDone, nil
}

// Step takes another step in the handshake between the server and client,
// where challenge is the data provided by client, and response is the data
// that should be sent back to the client. If done is true, the handshake
// is complete.
func (ss *Server) Step(challenge []byte) (response []byte, done bool,
	err error) {

	var responseStr *C.char
	var responseLen C.uint
	challengeStr := C.CString(string(challenge))
	challengeLen := C.uint(len(challenge))
	defer C.free(unsafe.Pointer(challengeStr))

	res := C.sasl_server_step(ss.server.ss_conn, challengeStr, challengeLen,
		&responseStr, &responseLen)
	if res != C.SASL_OK && res != C.SASL_CONTINUE {
		return nil, false, ss.newError(res, "Step")
	} else if res == C.SASL_OK {
		ss.handshakeDone = true
	}

	response = C.GoBytes(responseStr, C.int(responseLen))
	return response, ss.handshakeDone, nil
}

// Encode takes in a byteslice of data, then produces its encoded form to be
// sent to a client.
func (ss *Server) Encode(buf []byte) ([]byte, error) {
	return encode(ss.server.ss_conn, buf)
}

// Decode takes in a byteslice of data, then produces its encoded form to be
// sent to a client.
func (ss *Server) Decode(buf []byte) ([]byte, error) {
	return decode(ss.server.ss_conn, buf)
}

// GetUsername gets the username property from the sasl connection.
func (ss *Server) GetUsername() (string, error) {
	return getUsername(ss.server.ss_conn)
}

// GetSSF gets the security strength factor. If 0, then Encode/Decode are
// unnecesary.
func (ss *Server) GetSSF() (int, error) {
	ssfUint, err := getSSF(ss.server.ss_conn)
	return int(ssfUint), err
}

// addDanglingPtrs adds unsafe.Pointers that need to stay alive for the life of
// the server to a list so they can be freed when the server is no longer used.
func (ss *Server) addDanglingPtrs(ptrs ...unsafe.Pointer) {
	ss.ptrs = append(ss.ptrs, ptrs...)
}

// Free cleans up allocated memory in the Server.
func (ss *Server) Free() {
	for _, ptr := range ss.ptrs {
		C.free(ptr)
	}
	ss.ptrs = nil

	if ss.server == nil {
		return
	}

	if ss.server.ss_conn != nil {
		C.sasl_dispose(unsafe.Pointer(&ss.server.ss_conn))
		ss.server.ss_conn = nil
	}

	C.free(unsafe.Pointer(ss.server))
	ss.server = nil
}

// newError creates an error based on sasl_errstring / sasl_errdetail.
func (ss *Server) newError(res C.int, msg string) error {
	return newError(ss.server.ss_conn, res, msg)
}
