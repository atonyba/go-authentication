package providers

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
)

type customClaims struct {
	jwt.StandardClaims
	SID string
}

var key = []byte("my secret key 007 james bond rule the world from my mom's basement")

func createToken(sid string) (string, error) {

	cc := customClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		},
		SID: sid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cc)
	st, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("couldn't sign token in createToken %w", err)
	}
	return st, nil
}

func parseToken(tokenInput string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenInput, &customClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("parseWithClaims different algorithms used")
		}
		return key, nil
	})

	if err != nil {
		return "", fmt.Errorf("couldn't ParseWithClaims in parseToken %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("token not valid in parseToken")
	}

	return token.Claims.(*customClaims).SID, nil
}

func parseJwt(tokenString string, signingKeys jwtSigningKeys) *jwt.Token {
	log.Println("Entering parseJwt")

	claims := jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		for _, key := range signingKeys.Keys {
			log.Println("Comparing key ids:", key.KeyId, token.Header["kid"])

			if key.KeyId == token.Header["kid"] {
				return key.KeyId, nil
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

	for key, val := range claims {
		log.Printf("Key: %v, value: %v\n", key, val)
	}

	// log.Println("Checking if claims is valid")
	// if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
	// 	fmt.Println(claims["iss"], claims["nbf"])
	// } else {
	// 	fmt.Println(err)
	// }

	return token

}
