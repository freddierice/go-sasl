// sasl is a wrapper for the cyrus sasl library written for go.
// Right now it only supports clients, but that could change in the future.
// It is meant as a simple interface for interacting with a multitude of
// authentication mechanisms. Use it just as you would the C library --
// initialize a Client, call the client's Start method, then keep calling
// Step until the authentication has completed. After Client is done, call
// its Free method to cleanup any extra memory resources. The library was
// written such that multiple calls to Free is ok.
package sasl
