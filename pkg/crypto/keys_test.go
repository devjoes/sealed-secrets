package crypto

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"io"
	mathrand "math/rand"
	"reflect"
	"testing"
	"time"
)

// This is omg-not safe for real crypto use!
func testRand() io.Reader {
	return mathrand.New(mathrand.NewSource(42))
}

func TestSignKey(t *testing.T) {
	rand := testRand()

	key, err := rsa.GenerateKey(rand, 512)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	cert, err := SignKey(rand, key, time.Hour, "mycn")
	if err != nil {
		t.Errorf("signKey() returned error: %v", err)
	}

	if !reflect.DeepEqual(cert.PublicKey, &key.PublicKey) {
		t.Errorf("cert pubkey != original pubkey")
	}
}

func readKey(t *testing.T, seed string, input []byte) []byte {
	reader, e := SessionKeyProvider(seed, input)
	if e != nil {
		t.Error(e)
	}

	var buf = make([]byte, 1000)
	c, e := reader.Read(buf)

	if e != nil {
		t.Error(e)
	}
	if c != 1000 {
		t.Errorf("Expected 1000 bytes, recieved %d", c)
	}
	return buf
}
func TestSessionKeyProvider(t *testing.T) {
	rnd := testRand()
	input1 := make([]byte, 1000)
	input2 := make([]byte, 1000)
	rnd.Read(input1)
	rnd.Read(input2)

	random1 := readKey(t, "", input1)
	random2 := readKey(t, "", input1)
	if bytes.Equal(random1, random2) {
		t.Error("Default behaviour is not random!")
	}

	_, e := SessionKeyProvider(fmt.Sprintf("%31v", " "), input1)
	if e == nil {
		t.Error("Did not error with 31 char seed")
	}

	x := readKey(t, fmt.Sprintf("%32v", " "), input1)
	y := readKey(t, fmt.Sprintf("%32v", " "), input1)
	if !bytes.Equal(x, y) {
		t.Error("Same seed and input results in different output")
	}

	x = readKey(t, fmt.Sprintf("%32v", "a"), input1)
	y = readKey(t, fmt.Sprintf("%32v", " "), input1)
	if bytes.Equal(x, y) {
		t.Error("Different seed and same input results in same output")
	}

	x = readKey(t, fmt.Sprintf("%32v", " "), input1)
	y = readKey(t, fmt.Sprintf("%32v", " "), input2)
	fmt.Println(x)
	if bytes.Equal(x, y) {
		t.Error("Same seed and different input results in same output")
	}
}
