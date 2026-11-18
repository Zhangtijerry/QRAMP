class Fake:
 def md5(self,x): return x
hashlib=Fake()
hashlib.md5(b"x")
