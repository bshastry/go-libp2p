package fuzz

import (
	"crypto/ecdsa"
	"crypto/elliptic"
        "crypto/x509"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/binary"
	"time"
	"io"
	"math/big"
        "github.com/libp2p/go-libp2p/core/peer"
	p2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"golang.org/x/crypto/hkdf"
)

const info = "determinisitic cert"

type deterministicReader struct {
	reader           io.Reader
	singleByteReader io.Reader
}

func (r *deterministicReader) Read(p []byte) (n int, err error) {
	if len(p) == 1 {
		return r.singleByteReader.Read(p)
	}
	return r.reader.Read(p)
}

func FuzzCertParse(keyBytes []byte) int {
	reader := hkdf.New(sha256.New, keyBytes, nil, []byte(info))
	singleByteReader := hkdf.New(sha256.New, keyBytes, nil, []byte(info+" single byte"))

	deterministicHKDFReader := &deterministicReader{
		reader:           reader,
		singleByteReader: singleByteReader,
	}

	b := make([]byte, 8)
	if _, err := deterministicHKDFReader.Read(b); err != nil {
		return 1
	}
	serial := int64(binary.BigEndian.Uint64(b))
	if serial < 0 {
		serial = -serial
	}
	start := time.Now()
	end := start.Add(14*24*time.Hour)
	certTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{},
		NotBefore:             start,
		NotAfter:              end,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), deterministicHKDFReader)
	if err != nil {
		return 1
	}
	caBytes, err := x509.CreateCertificate(deterministicHKDFReader, certTempl, certTempl, caPrivateKey.Public(), caPrivateKey)
	if err != nil {
		return 1
	}
	cert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return 1
	}
	key, err := p2ptls.PubKeyFromCertChain([]*x509.Certificate{cert})
        if err != nil {
                return 1
        } else {
                _, err := peer.IDFromPublicKey(key)
                if err != nil {
                        return 1
                }
        }
        return 0
}

func FuzzEncodeDecodeID(data []byte) int {
	var id peer.ID
	if err := id.UnmarshalText(data); err == nil {
		encoded := peer.Encode(id)
		id2, err := peer.Decode(encoded)
		if err != nil {
			return 1
		}
		if id != id2 {
			return 1
		}
	}
	return 0
}
