package deuna

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"go.k6.io/k6/js/modules"
)

func init() {
	modules.Register("k6/x/deuna", new(Deuna))
}

type Deuna struct{}

func (*Deuna) Encriptar(message, publicKeyNoPEM string) string {
	// Decodificar la clave pública PEM desde una cadena
	block, _ := base64.StdEncoding.DecodeString(publicKeyNoPEM)

	// Parsear la clave pública en una estructura RSA
	publicKey, _ := x509.ParsePKIXPublicKey(block)

	// Convertir la clave a su tipo original (rsa.PublicKey)
	rsaPublicKey, _ := publicKey.(*rsa.PublicKey)

	// Encriptar el mensaje con la clave pública
	encryptedMessageBytes, _ := rsa.EncryptOAEP(
		sha1.New(),
		rand.Reader,
		rsaPublicKey,
		[]byte(message),
		[]byte(""),
	)

	return base64.StdEncoding.EncodeToString(encryptedMessageBytes)
}
