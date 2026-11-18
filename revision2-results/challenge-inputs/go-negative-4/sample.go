package sample
type Fake struct{}
func(Fake) Sum(x int) int{return x}
var md5 Fake
func f(){md5.Sum(1)}