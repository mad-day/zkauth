/*
MIT License

Copyright (c) 2017 Simon Schmidt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/* Zero knowledge authentication based on the socialist millionaire protocol. */
package zkauth

import "golang.org/x/crypto/sha3"
import "github.com/mad-day/hypercomplex"
import "math/big"
import "io"


func isOneOrZero(c hypercomplex.MultiComp) bool {
	var O,I big.Int
	O.SetInt64(0)
	I.SetInt64(1)
	if I.Cmp(c[0])<0 { return false }
	for _,cc := range c[1:] {
		if O.Cmp(cc)==0 { return false }
	}
	return true
}
func isEq(a, b hypercomplex.MultiComp) bool {
	for i,c := range a {
		if c.Cmp(b[i])!=0 { return false }
	}
	return true
}

type Handshake struct{
	hypercomplex.Modulus
	H hypercomplex.MultiComp
	A, Al, R []byte
	
	// The handshake has two different parties: a primary and a secondary.
	// The 'Primary' field of the two parties MUST differ.
	Primary bool
	G, Y, P, Q, ShouldC hypercomplex.MultiComp
	Message []byte // The message that should be authenticated.
	Failed bool // Will be 'true' if the handshake failed.
}

// First step of the handshake.
// mcLen must be a power of two.
// pkLen is the byte-length of secret random values
// (The protocol uses three).
func (h *Handshake) Step1(seed []byte,r io.Reader,mcLen,pkLen int) (A,Al hypercomplex.MultiComp, err error){
	{
		x := sha3.NewShake256()
		x.Write(seed)
		h.H,_ = h.Deterministic(x,mcLen)
	}
	h.Failed = false
	h.A  = make([]byte,pkLen)
	h.Al = make([]byte,pkLen)
	h.R  = make([]byte,pkLen)
	
	_,err = io.ReadFull(r,h.A)
	if err!=nil { return }
	_,err = io.ReadFull(r,h.Al)
	if err!=nil { return }
	_,err = io.ReadFull(r,h.R)
	if err!=nil { return }
	
	A  = h.Exp(h.H,h.A)
	Al = h.Exp(h.H,h.Al)
	return
}
func (h* Handshake) Step2(A,Al hypercomplex.MultiComp) (P,Q hypercomplex.MultiComp){
	if isOneOrZero(A) || isOneOrZero(Al) { h.Failed = true }
	h.G = h.Exp(A ,h.A)
	h.Y = h.Exp(Al,h.Al) 
	h.P = h.Exp(h.Y ,h.R)
	h.Q = h.Multiply( h.Exp(h.H ,h.R), h.Exp(h.G, h.Message) )
	P = h.P
	Q = h.Q
	return
}
func (h* Handshake) Step3(P,Q hypercomplex.MultiComp) hypercomplex.MultiComp{
	Q1 := h.Q
	Q2 := Q
	P1 := h.P
	P2 := P
	if isEq(Q1,Q2)||isEq(P1,P2) { h.Failed = true }
	if h.Primary {
		Q2 = h.Inverse(Q2)
		P2 = h.Inverse(P2)
	}else{
		Q1 = h.Inverse(Q1)
		P1 = h.Inverse(P1)
	}
	QQa := h.Exp(h.Multiply(Q1,Q2),h.Al)
	h.ShouldC = h.Multiply(P1,P2)
	return QQa
}
func (h* Handshake) Step4(QQb hypercomplex.MultiComp) {
	c := h.Exp(QQb,h.Al)
	if !isEq(c,h.ShouldC) { h.Failed = true }
}
