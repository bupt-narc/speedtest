package speedtest

import (
	"crypto/rand"

	"github.com/sirupsen/logrus"
)

func getRandomData(log *logrus.Entry, length int) []byte {
	data := make([]byte, length)
	if _, err := rand.Read(data); err != nil {
		log.Fatalf("Failed to generate random data: %s", err)
	}
	return data
}
