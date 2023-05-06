package ports

import (
	"math/rand"
)

func GetRandomPort() int {
	return rand.Intn(200)
}
