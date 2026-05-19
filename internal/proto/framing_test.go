package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestWriteRead_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := ServerHello{Nonce: []byte("0123456789abcdef0123456789abcdef"), ServerTime: 1735000000}
	if err := WriteMessage(&buf, in); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out ServerHello
	if err := ReadMessage(&buf, &out); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(out.Nonce) != string(in.Nonce) || out.ServerTime != in.ServerTime {
		t.Fatalf("round-trip mismatch: got %+v want %+v", out, in)
	}
}

func TestRead_OversizedHeaderRefused(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxMessageSize+1)
	r := bytes.NewReader(hdr[:])
	var out ServerHello
	if err := ReadMessage(r, &out); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("expected ErrMessageTooLarge, got %v", err)
	}
}

func TestWrite_OversizedPayloadRefused(t *testing.T) {
	huge := strings.Repeat("x", MaxMessageSize)
	v := struct {
		Big string `json:"big"`
	}{Big: huge}
	if err := WriteMessage(io.Discard, v); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("expected ErrMessageTooLarge, got %v", err)
	}
}

func TestRead_TruncatedBody(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 100)
	r := bytes.NewReader(append(hdr[:], 0x7b))
	var out map[string]any
	if err := ReadMessage(r, &out); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestRead_InvalidJSON(t *testing.T) {
	var buf bytes.Buffer
	body := []byte("not json")
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	buf.Write(hdr[:])
	buf.Write(body)
	var out ServerHello
	if err := ReadMessage(&buf, &out); err == nil {
		t.Fatal("expected unmarshal error")
	}
}
