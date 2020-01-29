package crypto

import (
	"crypto/rand"
	"fmt"
	"errors"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"hash"
	"io"
	"math/big"
	"time"
)

// GeneratePrivateKeyAndCert generates a keypair and signed certificate.
func GeneratePrivateKeyAndCert(keySize int, validFor time.Duration, cn string) (*rsa.PrivateKey, *x509.Certificate, error) {
	r := rand.Reader
	privKey, err := rsa.GenerateKey(r, keySize)
	if err != nil {
		return nil, nil, err
	}
	cert, err := SignKey(r, privKey, validFor, cn)
	if err != nil {
		return nil, nil, err
	}
	return privKey, cert, nil
}

// SignKey returns a signed certificate.
func SignKey(r io.Reader, key *rsa.PrivateKey, validFor time.Duration, cn string) (*x509.Certificate, error) {
	// TODO: use certificates API to get this signed by the cluster root CA
	// See https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/

	notBefore := time.Now()

	serialNo, err := rand.Int(r, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	cert := x509.Certificate{
		SerialNumber: serialNo,
		KeyUsage:     x509.KeyUsageEncipherOnly,
		NotBefore:    notBefore.UTC(),
		NotAfter:     notBefore.Add(validFor).UTC(),
		Subject: pkix.Name{
			CommonName: cn,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	data, err := x509.CreateCertificate(r, &cert, &cert, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(data)
}

func GenerateSessionKeyReader(sessionKeySource string, input []byte) (io.Reader, error) {
	fmt.Println(sessionKeySource)
	if len(sessionKeySource) == 0 {
		return rand.Reader, nil
	}
	fmt.Printf("%d\n", len(sessionKeySource))
	if len(sessionKeySource) < 32 {
		return nil, errors.New("Session key source must be at least 32 characters long")
	}

	return newFixedSessionKeyReader([]byte(sessionKeySource), input), nil
}

type Reader struct {
	hash      []byte
	current   []byte
	totalRead int
	sha       hash.Hash
}

func newFixedSessionKeyReader(seed []byte, input []byte) *Reader {
	sha := sha512.New()
	sLen := intToBytes(len(seed))
	iLen := intToBytes(len(sha.Sum(input)))

	var toHash []byte
	for _, a := range [][]byte{seed, sLen, input, iLen} {
		toHash = append(toHash, a...)
	}
	fmt.Println(sha.Sum(toHash))
	
	return &Reader{sha.Sum(toHash), nil, 0, sha}
}

func intToBytes(input int) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(input))
	return b
}

func (r *Reader) Read(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		if r.current == nil || i >= len(r.current) {
			r.current = r.sha.Sum(append(r.hash, intToBytes(i+r.totalRead)...))
			r.totalRead += i + 1
		}
		p[i] = r.current[i% len(r.current)]
	}
	return len(p), nil
}
