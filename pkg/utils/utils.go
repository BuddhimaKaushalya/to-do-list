package utils

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

func ParseBody(r *http.Request, data interface{}) error {
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&data)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	return nil
}

// GetHash generates a hash value for the given data using MD5 algorithm
func GetHash(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}
