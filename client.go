// sasl is a wrapper for the cyrus sasl library written for go.
// Right now it only supports clients, but that could change in the future.
// It is meant as a simple interface for interacting with a multitude of
// authentication mechanisms. Use it just as you would the C library --
// initialize a Client, call the client's Start method, then keep calling
// Step until the authentication has completed. After Client is done, call
// its Free method to cleanup any extra memory resources. The library was
// written such that multiple calls to Free is ok.
package sasl

// #cgo LDFLAGS: -lsasl2
// #cgo CFLAGS: -Wall
// #include <sasl/sasl.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
//
// typedef struct SaslClient_struct {
//     sasl_conn_t *sc_conn;
//     sasl_secret_t* sc_secret;
//     char *sc_username;
//     char *sc_authname;
//     char *sc_password;
// } SaslClient;
//
// SaslClient* new_client() {
//     SaslClient *ret = (SaslClient *)malloc(sizeof(SaslClient));
//     memset(ret, 0, sizeof(SaslClient));
//     return ret;
// }
//
// int cb_name(void *context, int id, const char **result, unsigned *len) {
//       SaslClient *sc = (SaslClient *)context;
//     if (id == SASL_CB_USER || (id == SASL_CB_AUTHNAME &&
//           !sc->sc_authname))
//         *result = sc->sc_username;
//     else if (id == SASL_CB_AUTHNAME)
//         *result = sc->sc_authname;
//     if (*result && len)
//         *len = strlen(*result);
//     return SASL_OK;
// }
//
// int cb_password(sasl_conn_t *conn, void *context, int id,
//       sasl_secret_t **psecret) {
//     SaslClient *sc = (SaslClient *)context;
//     size_t length = strlen(sc->sc_password);
//
//     if (id == SASL_CB_PASS) {
//         sc->sc_secret->len = length;
//         memcpy(sc->sc_secret->data, sc->sc_password, length);
//     } else {
//         sc->sc_secret->len = 0;
//     }
//
//     *psecret = sc->sc_secret;
//     return SASL_OK;
// }
//
// void add_callback(sasl_callback_t* cbs, void *context, unsigned long id,
//       int (*proc)(void)) {
//     cbs->id = id;
//     cbs->proc = proc;
//     cbs->context = context;
// }
//
// sasl_callback_t *generate_callbacks(SaslClient *sc, int username, int password) {
//     sasl_callback_t *cbs = (sasl_callback_t *)malloc(
//           sizeof(sasl_callback_t)*6);
//     int cbiter = 0;
//
//     add_callback(cbs + cbiter++, (void *)sc, SASL_CB_GETREALM, NULL);
//     if( username ) {
//         add_callback(cbs + cbiter++, (void *)sc, SASL_CB_USER,
//           (int (*)(void))cb_name);
//         add_callback(cbs + cbiter++, (void *)sc, SASL_CB_AUTHNAME,
//           (int (*)(void))cb_name);
//         if( password ) {
//             add_callback(cbs + cbiter++, (void *)sc, SASL_CB_PASS,
//               (int (*)(void))cb_password);
//         } else {
//             add_callback(cbs + cbiter++, (void *)sc, SASL_CB_PASS, NULL);
//         }
//     }
//     add_callback(cbs + cbiter++, (void *)sc, SASL_CB_LIST_END, NULL);
//     return cbs;
// }
//
import (
	"C"
)
import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"unsafe"
)

// Config is a struct that holds the information needed to initialize a
// SaslClient.
type Config struct {
	Username         string
	Authname         string
	Password         string
	ExternalUsername string

	MinSsf      uint32
	MaxSsf      uint32
	MaxBufsize  uint32
	ExternalSsf uint32
}

// Client is a structure that keeps the context of a sasl connection.
type Client struct {
	// libsaslwrapper
	client        *C.struct_SaslClient_struct
	ptrs          []unsafe.Pointer
	maxBufsize    int
	handshakeDone bool
}

// init starts the underlying sasl libraries so that plugins can be in place
// before we create any clients.
func init() {
	result := C.sasl_client_init(nil)
	if result != C.SASL_OK {
		log.Fatalf("could not start libsasl2: %v\n", C.sasl_errstring(result, nil, nil))
	}
}

// NewClient returns a new (initialized) client. If MaxSsf is not initialized,
// then it defaults to 65535.  If MaxBufsize is 0, then it defaults to 65535.
// If conf is nil, then use defaults.
func NewClient(service, host string, conf *Config) (*Client, error) {
	cl := &Client{}
	cl.client = C.new_client()

	cl.handshakeDone = false

	if conf == nil {
		conf = &Config{}
	}

	// fix defaults:
	if conf.MaxSsf == 0 {
		conf.MaxSsf = 65535
	}
	if conf.MaxBufsize == 0 {
		conf.MaxBufsize = 65535
	}

	cl.maxBufsize = int(conf.MaxBufsize)

	// generate callbacks for the client
	hasUsername, hasPassword := C.int(0), C.int(0)
	if len(conf.Username) != 0 {
		hasUsername = 1
	}
	if len(conf.Password) != 0 {
		hasPassword = 1
	}
	cbs := C.generate_callbacks(cl.client, hasUsername, hasPassword)

	flags := C.unsigned(0)
	if len(conf.Authname) == 0 && conf.Authname != conf.Username {
		flags |= C.SASL_NEED_PROXY
	}

	serviceStr := C.CString(service)
	hostStr := C.CString(host)
	cl.addDanglingPtrs(unsafe.Pointer(serviceStr), unsafe.Pointer(hostStr),
		unsafe.Pointer(cbs))
	res := C.sasl_client_new(serviceStr, hostStr, nil, nil, unsafe.Pointer(cbs),
		flags, unsafe.Pointer(&cl.client.sc_conn))
	if res != C.SASL_OK {
		err := cl.newError(res, "NewClient")
		cl.Free()
		return nil, err
	}

	secprops := C.sasl_security_properties_t{}
	secprops.min_ssf = C.sasl_ssf_t(conf.MinSsf)
	secprops.max_ssf = C.sasl_ssf_t(conf.MaxSsf)
	secprops.maxbufsize = C.unsigned(conf.MaxBufsize)
	secprops.property_names = nil
	secprops.property_values = nil
	secprops.security_flags = 0

	res = C.sasl_setprop(cl.client.sc_conn, C.SASL_SEC_PROPS,
		unsafe.Pointer(&secprops))
	if res != C.SASL_OK {
		err := cl.newError(res, "")
		cl.Free()
		return nil, err
	}

	if len(conf.ExternalUsername) != 0 {
		externalUsernameStrPtr := unsafe.Pointer(C.CString(conf.ExternalUsername))
		cl.addDanglingPtrs(externalUsernameStrPtr)
		res = C.sasl_setprop(cl.client.sc_conn, C.SASL_AUTH_EXTERNAL,
			externalUsernameStrPtr)
		if res != C.SASL_OK {
			err := cl.newError(res, "NewClient")
			cl.Free()
			return nil, err
		}

		res = C.sasl_setprop(cl.client.sc_conn, C.SASL_SSF_EXTERNAL,
			unsafe.Pointer(&conf.ExternalSsf))
		if res != C.SASL_OK {
			err := cl.newError(res, "NewClient")
			cl.Free()
			return nil, err
		}
	}

	return cl, nil
}

// Start uses sasl to select a mechanism for authentication. If information is
// needed from the user, then it is requested. If done is true, then the entire
// interaction is done. If done is false, continue with Step.
func (cl *Client) Start(mechlist []string) (mech string, response []byte,
	done bool, err error) {

	var prompt *C.sasl_interact_t
	var responseStr, mechStr *C.char
	var responseLen C.uint
	var res C.int

	prompt = nil
	mechlistExpanded := strings.Join(mechlist, ",")
	mechlistStr := C.CString(mechlistExpanded)
	defer C.free(unsafe.Pointer(mechlistStr))

	for {
		res = C.sasl_client_start(cl.client.sc_conn, mechlistStr,
			unsafe.Pointer(&prompt), unsafe.Pointer(&responseStr),
			&responseLen, unsafe.Pointer(&mechStr))
		if res != C.SASL_INTERACT {
			break
		}
		doPrompt(prompt)
	}

	if res != C.SASL_OK && res != C.SASL_CONTINUE {
		return "", nil, false, cl.newError(res, "Client Start")
	} else if res == C.SASL_OK {
		cl.handshakeDone = true
	}

	response = C.GoBytes(responseStr, C.int(responseLen))
	mech = C.GoString(mechStr)

	return mech, response, cl.handshakeDone, nil
}

// Step takes another step in the authentication. Response should be sent to
// the server, and done let's the client know that the SASL handshake is done.
func (cl *Client) Step(challenge []byte) (response []byte, done bool,
	err error) {

	var prompt *C.sasl_interact_t
	var responseStr *C.char
	var responseLen C.uint
	var res C.int

	challengeStr := C.CString(string(challenge))
	challengeLen := C.uint(len(challenge))
	for {
		res = C.sasl_client_step(cl.client.sc_conn, challengeStr, challengeLen,
			unsafe.Pointer(prompt), &responseStr, &responseLen)
		if res != C.SASL_INTERACT {
			break
		}
		doPrompt(prompt)
	}

	if res != C.SASL_OK && res != C.SASL_CONTINUE {
		return nil, false, cl.newError(res, "Step")
	} else if res == C.SASL_OK {
		cl.handshakeDone = true
	}

	response = C.GoBytes(responseStr, C.int(responseLen))

	return response, cl.handshakeDone, nil
}

// Encode takes in a byteslice of data, then produces its encoded form to be
// sent to a server.
func (cl *Client) Encode(in []byte) ([]byte, error) {
	if !cl.handshakeDone {
		return nil, fmt.Errorf("handshake has not been completed yet")
	}

	return encode(cl.client.sc_conn, in)
}

// Decode decodes the b bytes from the server. This can only be called after
// a SASL handshake has been created.
func (cl *Client) Decode(b []byte) (out []byte, err error) {
	if !cl.handshakeDone {
		return nil, fmt.Errorf("handshake has not been completed yet")
	}

	return decode(cl.client.sc_conn, b)
}

// Wrap encode/decodes data over the supplied reader. This can only be called
// after a SASL handshake has completed.
func (cl *Client) Wrap(rw io.ReadWriter) (io.ReadWriter, error) {
	if !cl.handshakeDone {
		return nil, fmt.Errorf("handshake has not been completed yet")
	}

	return wrap(cl, rw), nil
}

// WrapReader decodes data over the supplied reader. This can only be called
// after a SASL handshake has completed.
func (cl *Client) WrapReader(r io.Reader) (io.Reader, error) {
	if !cl.handshakeDone {
		return nil, fmt.Errorf("handshake has not been completed yet")
	}

	return wrapReader(cl, r), nil
}

// WrapWriter encodes data over the supplied writer. This can only be called
// after a SASL handshake has completed.
func (cl *Client) WrapWriter(w io.Writer) (io.Writer, error) {
	if !cl.handshakeDone {
		return nil, fmt.Errorf("handshake has not been completed yet")
	}

	return wrapWriter(cl, w), nil
}

// GetUsername gets the username property from the sasl connection.
func (cl *Client) GetUsername() (string, error) {
	return getUsername(cl.client.sc_conn)
}

// GetSSF gets the security strength factor. If 0, then Encode/Decode are
// unnecesary.
func (cl *Client) GetSSF() (int, error) {
	ssfUint, err := getSSF(cl.client.sc_conn)
	return int(ssfUint), err
}

// addDanglingPtrs adds unsafe.Pointers that need to stay alive for the life of
// the client to a list so they can be freed when the client is no longer used.
func (cl *Client) addDanglingPtrs(ptrs ...unsafe.Pointer) {
	cl.ptrs = append(cl.ptrs, ptrs...)
}

// Free cleans up allocated memory in the client.
func (cl *Client) Free() {
	for _, ptr := range cl.ptrs {
		C.free(ptr)
	}
	cl.ptrs = nil

	if cl.client == nil {
		return
	}

	if cl.client.sc_conn != nil {
		C.sasl_dispose(unsafe.Pointer(&cl.client.sc_conn))
		cl.client.sc_conn = nil
	}

	C.free(unsafe.Pointer(cl.client))
	cl.client = nil
}

// doPrompt takes user input from a prompt. If the prompt fails (i.e. if stdin
// is closed), then the default result will be used.
func doPrompt(prompt *C.sasl_interact_t) {
	promptStr := C.GoString(prompt.prompt)
	promptDefaultStr := C.GoString(prompt.defresult)

	if len(promptDefaultStr) == 0 {
		fmt.Printf("%s: ", promptStr)
	} else {
		fmt.Printf("%s [%s]: ", promptStr, promptDefaultStr)
	}

	response, err := bufio.NewReader(os.Stdin).ReadString('\n')
	response = strings.Trim(response, "\n")

	// if there is an error, then use the default.
	if err != nil {
		prompt.result = unsafe.Pointer(C.CString(response))
		prompt.len = C.uint(len(response))
	} else {
		prompt.result = unsafe.Pointer(C.strdup(prompt.defresult))
		prompt.len = C.uint(C.strlen(prompt.defresult))
	}
}

// newError creates an error based on sasl_errstring / sasl_errdetail.
func (cl *Client) newError(res C.int, msg string) error {
	return newError(cl.client.sc_conn, res, msg)
}
