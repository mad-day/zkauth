# zkauth
[![GoDoc](https://godoc.org/github.com/mad-day/zkauth?status.svg)](https://godoc.org/github.com/mad-day/zkauth)

Zero knowledge authentication based on the socialist millionaire protocol.


```go
	x := sha3.NewShake256()
	x.Write([]byte("1234"))
	
	seed := []byte("seedSEED")
	
	Ma := []byte("secret123")
	Mb := []byte("secret123")
	
	hs1 := new(zkauth.Handshake)
	hs2 := new(zkauth.Handshake)
	
	hs1.Mod = new(big.Int)
	hs1.Mod.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61",16)
	hs2.Mod = hs1.Mod
	
	hs1.Message = Ma
	hs2.Message = Mb
	hs1.Primary = true
	
	{
		A,Al,_ := hs1.Step1(seed,x,4,32)
		B,Bl,_ := hs2.Step1(seed,x,4,32)
		fmt.Println(A)
		fmt.Println(Al)
		fmt.Println(B)
		fmt.Println(Bl)
		Pa,Qa := hs1.Step2(B,Bl)
		Pb,Qb := hs2.Step2(A,Al)
		fmt.Println(Pa)
		fmt.Println(Qa)
		fmt.Println(Pb)
		fmt.Println(Qb)
		QQa := hs1.Step3(Pb,Qb)
		QQb := hs2.Step3(Pa,Qa)
		fmt.Println(QQa)
		fmt.Println(QQb)
		hs1.Step4(QQb)
		hs2.Step4(QQa)
	}
	
	fmt.Println("Failed?",hs1.Failed,hs2.Failed)
```