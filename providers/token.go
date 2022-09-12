package providers

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt"
)

func parseJwt(tokenString string, signingKeys jwtSigningKeys) *jwt.Token {
	log.Println("Entering parseJwt")

	claims := jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		for _, key := range signingKeys.Keys {
			if key.KeyId == token.Header["kid"] {
				publicKey, err := key.RSA()
				if err != nil {
					log.Println("Error while retrieving public key")
					return nil, err
				}
				return publicKey, nil
			}
		}
		return nil, errors.New("could not find validation key in IDP list")
	})

	if err != nil {
		log.Println("Error while parsing jwt with claims:", err)
	}

	if token == nil {
		return nil
	}

	log.Println("token.Valid:", token.Valid)

	for key, val := range claims {
		log.Printf("Key: %v, value: %v\n", key, val)
	}

	return token
}

// RSA parses a JSONKey and turns it into an RSA public key.
func (j *jwtSigningKey) RSA() (publicKey *rsa.PublicKey, err error) {

	// Check if the key has already been computed.
	if j.precomputed != nil {
		return j.precomputed.(*rsa.PublicKey), nil
	}

	// Confirm everything needed is present.
	if j.Exponent == "" || j.Modulus == "" {
		return nil, fmt.Errorf("%w: rsa", keyfunc.ErrMissingAssets)
	}

	// Decode the exponent from Base64.
	//
	// According to RFC 7518, this is a Base64 URL unsigned integer.
	// https://tools.ietf.org/html/rfc7518#section-6.3
	var exponent []byte
	if exponent, err = base64.RawURLEncoding.DecodeString(j.Exponent); err != nil {
		return nil, err
	}

	// Decode the modulus from Base64.
	var modulus []byte
	if modulus, err = base64.RawURLEncoding.DecodeString(j.Modulus); err != nil {
		return nil, err
	}

	// Create the RSA public key.
	publicKey = &rsa.PublicKey{}

	// Turn the exponent into an integer.
	//
	// According to RFC 7517, these numbers are in big-endian format.
	// https://tools.ietf.org/html/rfc7517#appendix-A.1
	publicKey.E = int(big.NewInt(0).SetBytes(exponent).Uint64())

	// Turn the modulus into a *big.Int.
	publicKey.N = big.NewInt(0).SetBytes(modulus)

	// Keep the public key so it won't have to be computed every time.
	j.precomputed = publicKey

	return publicKey, nil
}
