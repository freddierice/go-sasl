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
//     char        *ss_service;
//     char        *ss_hostname;
//     char        *ss_realm;
// } SaslServer;
//
// void free_server(SaslServer *);
//
// SaslServer* new_server(char *service, char * hostname, char *realm) {
//     SaslServer *ret = (SaslServer *)malloc(sizeof(SaslServer));
//     int res;
//
//     memset(ret, 0, sizeof(SaslServer));
//
//     ret->ss_service = service;
//     ret->ss_hostname = hostname;
//     ret->ss_realm = realm;
//
//     res = sasl_server_new(service, hostname, realm, NULL, NULL, NULL, 0,
//             &ret->ss_conn);
//     if( res != SASL_OK )
//         goto cleanup;
//
//
//     return ret;
// cleanup:
//     free_server(ret);
//     return NULL;
// }
//
// void free_server(SaslServer *ss) {
//     if( !ss ) return;
//
//     if( ss->ss_service ) free( ss->ss_service );
//     if( ss->ss_hostname ) free( ss->ss_hostname );
//     if( ss->ss_realm ) free( ss->ss_realm );
//
//     if( ss->ss_conn ) sasl_dispose( &ss->ss_conn );
// }
import (
	"C"
)
import (
	"fmt"
	"log"
	"strings"
	"unsafe"
)

// Server holds the information necesary to keep state within the server
type Server struct {
	// libsaslwrapper
	server        *C.struct_SaslServer_struct
	handshakeDone bool
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

	serviceStr := C.CString(service)
	hostStr := C.CString(host)
	realmStr := (*C.char)(unsafe.Pointer(nil))
	if realm != "" {
		realmStr = C.CString(realm)
	}
	ss.server = C.new_server(serviceStr, hostStr, realmStr)
	if ss.server == nil {
		return nil, fmt.Errorf("could not create the server")
	}

	return ss, nil
}

// ListMech provides a list of mechanisms with which the server can negotiate.
func (ss *Server) ListMech() ([]string, error) {
	var retstr *C.char

	prefixStr := C.CString("")
	defer C.free(unsafe.Pointer(prefixStr))
	sepStr := C.CString(",")
	defer C.free(unsafe.Pointer(sepStr))
	suffixStr := C.CString("")
	defer C.free(unsafe.Pointer(suffixStr))

	res := C.sasl_listmech(ss.server.ss_conn, nil, prefixStr, sepStr, suffixStr,
		&retstr, nil, nil)
	if res != C.SASL_OK {
		return nil, ss.newError(res, "ListMech")
	}

	sep := C.GoString(retstr)
	mechs := strings.Split(sep, ",")

	return mechs, nil
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

	res := C.sasl_server_start(ss.server.ss_conn, mechStr, challengeStr,
		challengeLen, &responseStr, &responseLen)
	if res != C.SASL_OK || res != C.SASL_CONTINUE {
		return nil, false, ss.newError(res, "Start")
	} else if res == C.SASL_OK {
		ss.handshakeDone = true
	}

	C.free(unsafe.Pointer(challengeStr))
	C.free(unsafe.Pointer(mechStr))

	response = C.GoBytes(unsafe.Pointer(responseStr), C.int(responseLen))
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

	response = C.GoBytes(unsafe.Pointer(responseStr), C.int(responseLen))
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

// Free cleans up allocated memory in the Server.
func (ss *Server) Free() {
	if ss.server == nil {
		return
	}

	C.free_server(ss.server)
	ss.server = nil
}

// newError creates an error based on sasl_errstring / sasl_errdetail.
func (ss *Server) newError(res C.int, msg string) error {
	return newError(ss.server.ss_conn, res, msg)
}
