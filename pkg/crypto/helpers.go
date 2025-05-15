package crypto

import (
	"bytes"
	"compress/flate"
	"io"
)

func compress(uncompressed []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	w, err := flate.NewWriter(buf, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	defer func() {
		// to be sure we close it
		_ = w.Close()
	}()

	if _, err := w.Write(uncompressed); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func decompress(compressed []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(compressed))
	defer func() {
		_ = r.Close()
	}()

	uncompressed, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return uncompressed, nil
}
