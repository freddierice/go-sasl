package sasl

import "io"

type Wrapable interface {
	Decode([]byte) ([]byte, error)
	Encode([]byte) ([]byte, error)
}

// wrappedReader is a struct that holds the underlying sasl connection
// and io.Reader.
type wrappedReader struct {
	wrap Wrapable
	r    io.Reader
}

// Read implements io.Reader.
func (wr *wrappedReader) Read(buf []byte) (n int, err error) {
	return read(buf, wr.wrap, wr.r)
}

// wrappedWriter is a struct that holds the underlying sasl connection
// and io.Writer.
type wrappedWriter struct {
	wrap Wrapable
	w    io.Writer
}

// Write implements the io.Writer.
func (ww *wrappedWriter) Write(buf []byte) (n int, err error) {
	return write(buf, ww.wrap, ww.w)
}

// wrappedReadWriter is a struct that holds the underlying sasl connection
// and io.ReadWriter.
type wrappedReadWriter struct {
	wrap Wrapable
	rw   io.ReadWriter
}

// Read implements io.ReadWriter.
func (wrw *wrappedReadWriter) Read(buf []byte) (n int, err error) {
	return read(buf, wrw.wrap, wrw.rw)
}

// Write implements io.ReadWriter.
func (wrw *wrappedReadWriter) Write(buf []byte) (n int, err error) {
	return write(buf, wrw.wrap, wrw.rw)
}

// wrap creates a io.ReadWriter that encodes and decodes data sent over a
// sasl connection.
func wrap(wrapable Wrapable, readwriter io.ReadWriter) io.ReadWriter {
	return &wrappedReadWriter{
		wrap: wrapable,
		rw:   readwriter,
	}
}

// wrapReader creates an io.Reader that decodes data from a sasl server/client.
func wrapReader(wrapable Wrapable, reader io.Reader) io.Reader {
	return &wrappedReader{
		wrap: wrapable,
		r:    reader,
	}
}

// wrapWriter creates an io.Writer that encodes data to a sasl server/client.
func wrapWriter(wrapable Wrapable, writer io.Writer) io.Writer {
	return &wrappedWriter{
		wrap: wrapable,
		w:    writer,
	}
}

// read decodes the buffer and passes it along to the underlying reader.
func read(buf []byte, wrap Wrapable, r io.Reader) (n int, err error) {
	b, err := wrap.Decode(buf)
	if err != nil {
		return 0, err
	}
	return r.Read(b)
}

// write encodes the buffer and passes it along to the underlying writer.
func write(buf []byte, wrap Wrapable, w io.Writer) (n int, err error) {
	b, err := wrap.Encode(buf)
	if err != nil {
		return 0, err
	}
	return w.Write(b)
}
