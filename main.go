package main

//BeginJJ
import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
)

// 完全兼容 Java Random 的算法
type JavaRandom struct {
	seed int64
}

const javaMultiplier = 0x5DEECE66D
const javaAddend = 0xB
const javaMask = (1 << 48) - 1

func NewJavaRandom(seed int64) *JavaRandom {
	return &JavaRandom{seed: (seed ^ javaMultiplier) & javaMask}
}

func (r *JavaRandom) next(bits int) int32 {
	r.seed = (r.seed*javaMultiplier + javaAddend) & javaMask
	return int32(uint64(r.seed) >> (48 - bits))
}

func (r *JavaRandom) nextInt(n int) int32 {
	if n <= 0 {
		panic("n must be positive")
	}
	if (n & -n) == n {
		return int32((int64(n) * int64(r.next(31))) >> 31)
	}
	var bits, val int32
	for {
		bits = r.next(31)
		val = bits % int32(n)
		if bits-int32(val)+int32(n-1) >= 0 {
			return val
		}
	}
}

func (r *JavaRandom) nextLong() int64 {
	return (int64(r.next(32)) << 32) + int64(r.next(32))
}

// --- 以下为主逻辑 ---

func main() {
  //./finalshell_mac --password eU15IxpjG1qmvvgmJGZFh9O5AIo0lHQgqHxJ6Hs2y4w=
	var password string
	flag.StringVar(&password, "password", "", "hide the ComponentCheck result")

	flag.Parse()

	if password == "" {
		fmt.Println("password is empty")
		return
	}

	out, err := decodePass(password)
	if err != nil {
		panic(err)
	}
	fmt.Println(out)
}

func decodePass(data string) (string, error) {
	if data == "" {
		return "", nil
	}
	buf, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	head := buf[:8]
	body := buf[8:]
	key := ranDomKey(head)
	dec, err := desDecode(body, key[:8])
	if err != nil {
		return "", err
	}
	dec = pkcs5Unpad(dec)
	return string(dec), nil
}

func ranDomKey(head []byte) []byte {
	r := NewJavaRandom(int64(head[5]))
	ks := int64(3680984568597093857) / int64(r.nextInt(127))
	r1 := NewJavaRandom(ks)

	t := int(head[0])
	for i := 0; i < t; i++ {
		r1.nextLong()
	}

	n := r1.nextLong()
	r2 := NewJavaRandom(n)

	ld := []int64{
		int64(head[4]),
		r2.nextLong(),
		int64(head[7]),
		int64(head[3]),
		r2.nextLong(),
		int64(head[1]),
		r1.nextLong(),
		int64(head[2]),
	}

	buf := new(bytes.Buffer)
	for _, l := range ld {
		_ = binary.Write(buf, binary.BigEndian, l)
	}
	hash := md5.Sum(buf.Bytes())
	return hash[:]
}

func desDecode(data, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		return nil, fmt.Errorf("data not multiple of DES block size")
	}
	dst := make([]byte, len(data))
	mode := newECBDecrypter(block)
	mode.CryptBlocks(dst, data)
	return dst, nil
}

// --- ECB 实现 ---
type ecb struct {
	b         cipher.Block
	blockSize int
}
type ecbDecrypter ecb

func newECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(&ecb{b: b, blockSize: b.BlockSize()})
}
func (x *ecbDecrypter) BlockSize() int { return x.blockSize }
func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("ecbDecrypter: input not full blocks")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

// --- PKCS5 unpad ---
func pkcs5Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padLen := int(data[len(data)-1])
	if padLen <= 0 || padLen > len(data) {
		return data
	}
	return data[:len(data)-padLen]
}
