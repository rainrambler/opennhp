package core

import (
	"encoding/base64"
	"fmt"
	"math/big"

	_ "github.com/emmansun/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm2"
)

func convertPrivKey(d *big.Int) (*sm2.PrivateKey, error) {
	priv := new(sm2.PrivateKey)
	c := sm2.P256Sm2()
	priv.PublicKey.Curve = c
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(d.Bytes())

	return priv, nil
}

// 验证私钥和公钥是否有效
func verifySM2Key(privateKey *big.Int, publicKey *sm2.PublicKey) bool {
	// 验证私钥范围
	n := sm2.P256Sm2().Params().N
	if privateKey.Cmp(big.NewInt(1)) < 0 || privateKey.Cmp(n) >= 0 {
		return false
	}

	pk, err := convertPrivKey(privateKey)
	if err != nil {
		fmt.Printf("Cannot convert to private key: %s (%v)\n", privateKey.String(), err)
		return false
	}

	PrintKey("Priv D", pk.D.Bytes())
	PrintKey("Matched X", pk.X.Bytes())
	PrintKey("Matched Y", pk.Y.Bytes())

	// 验证公钥坐标
	return pk.X.Cmp(publicKey.X) == 0 && pk.Y.Cmp(publicKey.Y) == 0
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
	publicKey := &sm2.PublicKey{
		Curve: sm2.P256Sm2(),
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
	publicKey := &sm2.PublicKey{
		Curve: sm2.P256Sm2(),
		X:     x, // 替换为实际公钥X坐标
		Y:     y, // 替换为实际公钥Y坐标
	}

	res := verifySM2Key(pvint, publicKey)
	if res {
		fmt.Println("公钥对应私钥")
	} else {
		fmt.Println("公钥不对应私钥")
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

func IsOnCurveSM2(x, y *big.Int) bool {
	PrintKey("X", x.Bytes())
	PrintKey("Y", y.Bytes())

	res := sm2.P256Sm2().IsOnCurve(x, y)
	if res {
		fmt.Println("SM2 公钥有效性: 有效")
	} else {
		fmt.Println("SM2 公钥有效性: 无效")
	}
	return res
}
