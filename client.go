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
//     sasl_callback_t *sc_cbs;
//     char *sc_hostname;
//     char *sc_service;
//     char *sc_username;
//     char *sc_authname;
//     char *sc_password;
//     char *sc_realm;
// } SaslClient;
//
// void generate_callbacks(SaslClient *);
//
// SaslClient* new_client(char *hostname, char *service, char *username,
//       char *authname, char *password, char *realm,
//       char *external_username, unsigned external_ssf, unsigned flags,
//       unsigned min_ssf, unsigned max_ssf, unsigned maxbufsize) {
//     int res;
//     sasl_security_properties_t secprops;
//     SaslClient *ret = (SaslClient *)malloc(sizeof(SaslClient));
//     memset(ret, 0, sizeof(SaslClient));
//
//     ret->sc_hostname = hostname;
//     ret->sc_service  = service;
//     ret->sc_username = username;
//     ret->sc_authname = authname;
//     ret->sc_password = password;
//     ret->sc_realm    = realm;
//
//     generate_callbacks(ret);
//
//     res = sasl_client_new(ret->sc_service, ret->sc_hostname, 0, 0,
//             ret->sc_cbs, flags, &ret->sc_conn);
//     if( res != SASL_OK )
//         goto cleanup;
//
//     if( external_username ){
//	       res = sasl_setprop(ret->sc_conn, SASL_AUTH_EXTERNAL,
//		           external_username);
//         if( res != SASL_OK )
//             goto cleanup;
//
//         res = sasl_setprop(ret->sc_conn, SASL_SSF_EXTERNAL, &external_ssf);
//         if( res != SASL_OK )
//             goto cleanup;
//     }
//
//     memset(&secprops, 0, sizeof(sasl_security_properties_t));
//     secprops.min_ssf = min_ssf;
//     secprops.max_ssf = max_ssf;
//     secprops.maxbufsize = maxbufsize;
//
//     res = sasl_setprop(ret->sc_conn, SASL_SEC_PROPS, &secprops);
//     if( res != SASL_OK )
//         goto cleanup;
//     return ret;
// cleanup:
//     free(ret);
//     return NULL;
// }
//
// void free_client(SaslClient *sc) {
//     if( !sc )
//         return;
//
//     // clear simple fields
//     if( sc->sc_secret )
//         free(sc->sc_secret);
//     if( sc->sc_cbs )
//         free(sc->sc_cbs);
//     if( sc->sc_hostname )
//         free(sc->sc_hostname);
//     if( sc->sc_service )
//         free(sc->sc_service);
//     if( sc->sc_username )
//         free(sc->sc_username);
//     if( sc->sc_authname )
//         free(sc->sc_authname);
//     if( sc->sc_password )
//         free(sc->sc_password);
//     if( sc->sc_realm )
//         free(sc->sc_realm);
//
//     //dispose of the connection
//     if( sc->sc_conn )
//         sasl_dispose(&sc->sc_conn);
//
//     free(sc);
// }
//
// int cb_name(SaslClient *sc, int id, const char **result, unsigned *len) {
//     if (id == SASL_CB_USER )
//         *result = sc->sc_username;
//     else if (id == SASL_CB_AUTHNAME)
//         *result = sc->sc_authname;
//     if (*result && len)
//         *len = strlen(*result);
//     return SASL_OK;
// }
//
// int cb_password(sasl_conn_t *conn, SaslClient *sc, int id,
//       sasl_secret_t **psecret) {
//     size_t length = strlen(sc->sc_password);
//
//     if (id == SASL_CB_PASS) {
//         if( sc->sc_secret )
//             free(sc->sc_secret);
//		   sc->sc_secret = (sasl_secret_t *)malloc(sizeof(sasl_secret_t)+length+1);
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
// int cb_getrealm(SaslClient *sc, int id, const char **availrealms,
//   const char **result) {
//     *result = (const char *)sc->sc_realm;
//     return SASL_OK;
// }
//
// int cb_canon_user(sasl_conn_t *conn, SaslClient *sc, const char *user,
//       unsigned userLen, unsigned flags, const char *user_realm, char *out,
//       unsigned out_max, unsigned *out_len) {
//     if( user_realm )
//	       *out_len = (unsigned)snprintf(out, out_max, "%s@%s", user,
//                      user_realm);
//     else
//         *out_len = (unsigned)snprintf(out, out_max, "%s", user);
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
// void generate_callbacks(SaslClient *sc) {
//     sasl_callback_t *cbs = (sasl_callback_t *)malloc(
//           sizeof(sasl_callback_t)*10);
//     int cbiter = 0;
//
//     if( sc->sc_realm ) {
//         add_callback(cbs + cbiter++, (void *)sc, SASL_CB_GETREALM,
//           (int (*)(void))cb_getrealm);
//     } else {
//         add_callback(cbs + cbiter++, (void *)sc, SASL_CB_GETREALM, NULL);
//     }
//         add_callback(cbs + cbiter++, (void *)sc, SASL_CB_USER,
//           (int (*)(void))cb_name);
//         add_callback(cbs + cbiter++, (void *)sc, SASL_CB_AUTHNAME,
//           (int (*)(void))cb_name);
//         if( sc->sc_password ) {
//             add_callback(cbs + cbiter++, (void *)sc, SASL_CB_PASS,
//               (int (*)(void))cb_password);
//         } else {
//             add_callback(cbs + cbiter++, (void *)sc, SASL_CB_PASS, NULL);
//         }
//
//     add_callback(cbs + cbiter++, (void *)sc, SASL_CB_CANON_USER,
//       (int (*)(void))cb_canon_user);
//     add_callback(cbs + cbiter++, (void *)sc, SASL_CB_LIST_END, NULL);
//
//     sc->sc_cbs = cbs;
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
	Realm            string

	MinSsf      uint32
	MaxSsf      uint32
	MaxBufsize  uint32
	ExternalSsf uint32
}

// Client is a structure that keeps the context of a sasl connection.
type Client struct {
	// libsaslwrapper
	client        *C.struct_SaslClient_struct
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

	// fix defaults:
	if conf == nil {
		conf = &Config{}
	}
	if conf.MaxSsf == 0 {
		conf.MaxSsf = 65535
	}
	if conf.MaxBufsize == 0 {
		conf.MaxBufsize = 65535
	}

	// create the client
	cl := &Client{
		handshakeDone: false,
		maxBufsize:    int(conf.MaxBufsize),
	}

	// setup c client
	hostStr := C.CString(host)
	serviceStr := C.CString(service)
	var usernameStr, authnameStr, passwordStr, realmStr,
		externalUsernameStr *C.char
	flags := C.unsigned(0)
	if len(conf.Username) > 0 {
		usernameStr = C.CString(conf.Username)
	}
	if len(conf.Authname) > 0 {
		authnameStr = C.CString(conf.Authname)
	}
	if len(conf.Password) > 0 {
		passwordStr = C.CString(conf.Password)
	}
	if len(conf.Realm) > 0 {
		realmStr = C.CString(conf.Realm)
	}
	if len(conf.ExternalUsername) > 0 {
		externalUsernameStr = C.CString(conf.ExternalUsername)
		defer C.free(unsafe.Pointer(externalUsernameStr))
	}
	if len(conf.Authname) == 0 && conf.Authname != conf.Username {
		flags |= C.SASL_NEED_PROXY
	}
	cl.client = C.new_client(hostStr, serviceStr, usernameStr, authnameStr,
		passwordStr, realmStr, externalUsernameStr, C.uint(conf.ExternalSsf),
		flags, C.uint(conf.MinSsf), C.uint(conf.MaxSsf), C.uint(conf.MaxBufsize))
	if cl.client == nil {
		cl.Free()
		return nil, fmt.Errorf("could not create the client")
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
			&prompt, &responseStr,
			&responseLen, &mechStr)
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

	response = C.GoBytes(unsafe.Pointer(responseStr), C.int(responseLen))
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
			&prompt, &responseStr, &responseLen)
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

	response = C.GoBytes(unsafe.Pointer(responseStr), C.int(responseLen))

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

// Free cleans up allocated memory in the client.
func (cl *Client) Free() {
	if cl.client != nil {
		C.free_client(cl.client)
		cl.client = nil
	}
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
