package sasl

// #cgo LDFLAGS: -lsasl2
// #include <sasl/sasl.h>
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
//         !sc->sc_authname)) {
//         *result = sc->sc_username;
//         *len = strlen(sc->sc_username);
//     } else if (id == SASL_CB_AUTHNAME) {
//         *result = sc->sc_authname;
//         *len = strlen(sc->sc_authname);
//     }
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
	"fmt"
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
	client *C.struct_SaslClient_struct
}

// NewClient returns a new client with a large buffer and maxSsf.
func NewClient(service, host string, conf *Config) (*Client, error) {
	c := &Client{}
	c.client = C.new_client()

	// fix defaults:
	if conf.MaxSsf == 0 {
		conf.MaxSsf = 65535
	}
	if conf.MaxBufsize == 0 {
		conf.MaxBufsize = 65535
	}

	// generate callbacks for the client
	hasUsername, hasPassword := C.int(0), C.int(0)
	if len(conf.Username) != 0 {
		hasUsername = 1
	}
	if len(conf.Password) != 0 {
		hasPassword = 1
	}
	cbs := C.generate_callbacks(c.client, hasUsername, hasPassword)

	flags := C.unsigned(0)
	if len(conf.Authname) == 0 && conf.Authname != conf.Username {
		flags |= C.SASL_NEED_PROXY
	}

	serviceStr := C.CString(service)
	hostStr := C.CString(host)
	defer C.free(unsafe.Pointer(serviceStr))
	defer C.free(unsafe.Pointer(hostStr))
	res := C.sasl_client_new(serviceStr, hostStr, nil, nil, unsafe.Pointer(cbs),
		flags, unsafe.Pointer(&c.client.sc_conn))
	if res != C.SASL_OK {
		return nil, c.newError(res, "NewClient")
	}

	secprops := C.sasl_security_properties_t{}
	secprops.min_ssf = C.sasl_ssf_t(conf.MinSsf)
	secprops.max_ssf = C.sasl_ssf_t(conf.MaxSsf)
	secprops.maxbufsize = C.unsigned(conf.MaxBufsize)
	secprops.property_names = nil
	secprops.property_values = nil
	secprops.security_flags = 0

	res = C.sasl_setprop(c.client.sc_conn, C.SASL_SEC_PROPS,
		unsafe.Pointer(&secprops))
	if res != C.SASL_OK {
		return nil, c.newError(res, "")
	}

	return c, nil
}

//

// Free the client, since it was malloced.
func (c *Client) Free() {
	if c.client == nil {
		return
	}

	if c.client.sc_conn != nil {
		C.sasl_dispose(unsafe.Pointer(&c.client.sc_conn))
		c.client.sc_conn = nil
	}

	C.free(unsafe.Pointer(c.client))
	c.client = nil
}

// newError creates an error based on sasl_errstring / sasl_errdetail.
func (c *Client) newError(res C.int, msg string) error {
	var errMsg *C.char

	if c.client == nil {
		errMsg = C.sasl_errstring(res, nil, nil)
	} else {
		errMsg = C.sasl_errdetail(c.client.sc_conn)
	}

	return fmt.Errorf("err in %v: %v\n", msg, errMsg)
}
