package KGC

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	_ "github.com/tjfoc/gmsm/sm2"
)

func PrintKey(keyname string, bs []byte) {
	if len(bs) == 0 {
		fmt.Printf("%s nil\n", keyname)
		return
	}
	key64 := base64.StdEncoding.EncodeToString(bs)
	fmt.Printf("%s BASE64: [%s] %d Bytes: %X...%X\n",
		keyname, key64, len(bs), bs[:4], bs[len(bs)-4:])
}

// 验证私钥和公钥是否有效
func verifySM2Key(privateKey *big.Int, publicKey *ecdsa.PublicKey) bool {
	// 验证私钥范围
	n := sm2.P256().Params().N
	if privateKey.Cmp(big.NewInt(1)) < 0 || privateKey.Cmp(n) >= 0 {
		return false
	}

	// 计算公钥
	computedPublicKey := new(ecdsa.PublicKey)
	computedPublicKey.Curve = sm2.P256()
	computedPublicKey.X, computedPublicKey.Y = computedPublicKey.Curve.ScalarBaseMult(privateKey.Bytes())

	PrintKey("Computed X", computedPublicKey.X.Bytes())
	PrintKey("Computed Y", computedPublicKey.Y.Bytes())

	// 验证公钥坐标
	return computedPublicKey.X.Cmp(publicKey.X) == 0 && computedPublicKey.Y.Cmp(publicKey.Y) == 0
}

func IsInEC(pubkey, privkey string) bool {
	pbbs, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		panic(err)
	}

	pvbs, err := base64.StdEncoding.DecodeString(privkey)
	if err != nil {
		panic(err)
	}

	pvint := new(big.Int)
	pvint.SetBytes(pvbs)
	PrintKey("PrivKey", pvbs)

	x := new(big.Int)
	x.SetBytes(pbbs[:32])
	y := new(big.Int)
	y.SetBytes(pbbs[32:])

	PrintKey("X", x.Bytes())
	PrintKey("Y", y.Bytes())

	// 示例私钥（需要替换为实际私钥）
	//privateKey := new(big.Int).SetInt64(123456789) // 需要在[1, n-1]范围内

	// 示例公钥（需要替换为实际公钥坐标）
	publicKey := &ecdsa.PublicKey{
		Curve: sm2.P256(),
		X:     x, // 替换为实际公钥X坐标
		Y:     y, // 替换为实际公钥Y坐标
	}

	res := verifySM2Key(pvint, publicKey)
	if res {
		fmt.Println("公钥有效性: 有效")
	} else {
		fmt.Println("公钥有效性: 无效")
	}
	return res
}

func IsOnCurve(priv, x, y *big.Int) bool {
	pvint := priv
	PrintKey("PrivKey", pvint.Bytes())

	PrintKey("X", x.Bytes())
	PrintKey("Y", y.Bytes())

	// 示例私钥（需要替换为实际私钥）
	//privateKey := new(big.Int).SetInt64(123456789) // 需要在[1, n-1]范围内

	// 示例公钥（需要替换为实际公钥坐标）
	publicKey := &ecdsa.PublicKey{
		Curve: sm2.P256(),
		X:     x, // 替换为实际公钥X坐标
		Y:     y, // 替换为实际公钥Y坐标
	}

	res := verifySM2Key(pvint, publicKey)
	if res {
		fmt.Println("公钥有效性: 有效")
	} else {
		fmt.Println("公钥有效性: 无效")
	}
	return res
}

func IsOnCurveBase64(privs, xs, ys string) bool {
	privb, err := base64.StdEncoding.DecodeString(privs)
	if err != nil {
		panic(err)
	}

	xb, err := base64.StdEncoding.DecodeString(xs)
	if err != nil {
		panic(err)
	}

	yb, err := base64.StdEncoding.DecodeString(ys)
	if err != nil {
		panic(err)
	}

	priv := new(big.Int).SetBytes(privb)
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)

	return IsOnCurve(priv, x, y)
}
