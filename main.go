package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/google/tink/go/kwp/subtle"
)

func main() {

	// Define target key (256-bit)
	key := []byte("YELLOW SUBMARINEYELLOW SUBMARINE")

	// Retreeve warpping key from Vault (4096-bit RSA key)
	wrappingKeyString := "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnE8Pk4/JbV7/h7KuzMCy\nN5maw7NDAKmhwzBn/x/qnfm1YIkW79wzpScysdgykUfE5vYaEYjPPcs8JF8Sy876\ncwp+YyVcnWWDEQUFXfeTGAQ4TMWpcVLm80vHwML+dQxSVsDIzwFyNp36gPi1mhp5\nJLGp+cGjUoDyxAxe2D3pWjv7qT5Ew57Ff7HBK+CG5On5WL/0NKCo0aEB4K2YrEFU\nye6QUEyIUhhT7s6OSy6iY3mOZoXdo2DYpzoyt86pDQ1nfcyoMB+qGjjr6JXY5fb0\n+MIFTvJV0adniEeCxIMhMx5f/QPyIZl4ba73dYWpb0vyOfFAMm5u2EzRX/1IOKDF\nZHTuIZooHY/Mx0Je52P5wWL/iCFHqYREOoW9ohw+R9+Lqxeri61b81EcQS/N2KA7\nmk3d3z3edVMcnkjYgOZREh4AesEm+t9shAciizL3ZksPlbO9yXDuvoFkOdKNsIhP\nCm7E8Vk1cYSQJQCQH0AtYUA2KAwdMKqaKLWb2oXes71KAMYFinmI6+ZGTiUQkuMK\nu3j+8s6sG2Sz7+725KS0dsa2o78lz3N5c/GoIUS9ysDffr80F/4H6QGkk/+D1eeZ\nud8ZBcI8u0ZX/kOEhcODYlsrSvhsJiIqZW7GPQhq0JY2jW8eVSGybIOOPYTIY4nq\ncHke+qUJDv6ZKmZpQLYTorMCAwEAAQ==\n-----END PUBLIC KEY-----\n"

	keyBlock, _ := pem.Decode([]byte(wrappingKeyString))
	parsedKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	// Generate an ephemeral 256-bit AES key.
	ephemeralAESKey := make([]byte, 32)
	rand.Read(ephemeralAESKey)

	// Wrap the target key using the ephemeral AES key with AES-KWP.
	wrapKWP, err := subtle.NewKWP(ephemeralAESKey)
	if err != nil {
		panic(err)
	}
	wrappedTargetKey, err := wrapKWP.Wrap(key)
	if err != nil {
		panic(err)
	}

	// Wrap the AES key under the Vault wrapping key using RSAES-OAEP with MGF1 and either SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512.
	wrappedAESKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		parsedKey.(*rsa.PublicKey),
		ephemeralAESKey,
		[]byte{},
	)
	if err != nil {
		panic(err)
	}

	combinedCiphertext := append(wrappedAESKey, wrappedTargetKey...)
	base64Ciphertext := base64.StdEncoding.EncodeToString(combinedCiphertext)

	fmt.Printf("%s", base64Ciphertext)
}
