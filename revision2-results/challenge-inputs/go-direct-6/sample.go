package sample
import ("crypto/rsa";"crypto/rand")
func f(){ rsa.GenerateKey(rand.Reader,2048) }
