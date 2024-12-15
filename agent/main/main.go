package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/OpenNHP/opennhp/agent"
	"github.com/OpenNHP/opennhp/core"
	"github.com/OpenNHP/opennhp/version"
	"github.com/emmansun/gmsm/sm2"
	_ "github.com/tjfoc/gmsm/sm2"
	"github.com/urfave/cli/v2"
)

// 新增 KeyResponse 结构体，存储从 KGC 接收到的密钥信息
type KeyResponse struct {
	PartialPrivateKey string `json:"partial_private_key"`
	PartialPublicKeyX string `json:"partial_public_key_x"`
	PartialPublicKeyY string `json:"partial_public_key_y"`
	Gx                string `json:"Gx"`
	Gy                string `json:"Gy"`
	N                 string `json:"N"`
}

//const KGC_IP = "192.168.3.14"

const KGC_IP = "127.0.0.1"

func main() {
	app := cli.NewApp()
	app.Name = "nhp-agent"
	app.Usage = "agent entity for NHP protocol"
	app.Version = version.Version

	runCmd := &cli.Command{
		Name:  "run",
		Usage: "create and run agent process for NHP protocol",
		Action: func(c *cli.Context) error {
			return runApp()
		},
	}

	// 保留原有的 keygenCmd 逻辑
	keygenCmd := &cli.Command{
		Name:  "keygen",
		Usage: "generate key pairs for NHP devices",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "curve", Value: false, DisableDefaultText: true, Usage: "generate curve25519 keys"},
			&cli.BoolFlag{Name: "sm2", Value: false, DisableDefaultText: true, Usage: "generate sm2 keys"},
		},
		Action: func(c *cli.Context) error {
			var e core.Ecdh
			if c.Bool("sm2") {
				e = core.NewECDH(core.ECC_SM2)
			} else {
				e = core.NewECDH(core.ECC_CURVE25519)
			}
			pub := e.PublicKeyBase64()
			priv := e.PrivateKeyBase64()
			fmt.Println("Private key: ", priv)
			fmt.Println("Public key: ", pub)
			return nil
		},
	}

	// 新增命令 kgc-interact，用于与 KGC 服务交互并生成完整密钥
	kgcCmd := &cli.Command{
		Name:  "kgc-interact",
		Usage: "interact with KGC service to get partial keys and generate full key pair",
		Action: func(c *cli.Context) error {
			// 用户输入邮箱
			var email string
			user_name := core.RandomString(5)
			email = user_name + "@qq.com"
			//fmt.Print("Enter your email: ")
			//fmt.Scanln(&email)
			fmt.Printf("UserID (email): %s\n", email)

			// 定义邮箱格式的正则表达式
			var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

			// 验证邮箱格式
			if !emailRegex.MatchString(email) {
				fmt.Println("Invalid email format. Please enter a valid email address.")
				return nil
			}

			// 提取域名
			parts := strings.Split(email, "@")
			domain := parts[1]

			// 检查域名是否存在
			_, err := net.LookupMX(domain)
			if err != nil {
				fmt.Printf("Domain '%s' does not exist or has no MX records.\n", domain)
				return nil
			}

			//dastr, userpubk := core.Gen_sm2_keypair("rgevcbdh")
			//da_bytes := core.Hex_to_bytes(dastr)
			//dA_ := new(big.Int).SetBytes(da_bytes)
			//core.Dbg_print_bigint("da priv", dA_)

			// 椭圆曲线的参数
			_, _, N := core.GetSM2CurveParams()

			// 产生随机数 d'A ∈ [1, n−1]
			var el core.ElapseLogger
			el.Start("UA")

			dA_, err := rand.Int(rand.Reader, N)
			if err != nil {
				log.Fatalf("Failed to generate random d'A: %v", err)
			}

			// 用户A计算UA=[d'A]G，并将标识IDA和UA提交KGC；
			UA := core.GenPubKeyfromPrivKey(dA_)
			el.Stop("UA")

			//core.PrintKey("dA_", dA_.Bytes())
			//core.PrintKey("UA X", UA.X.Bytes())
			//core.PrintKey("UA Y", UA.Y.Bytes())
			userpubk := core.PublicKeyToString(UA)

			el.Start("TA")
			// 继续与 KGC 交互的流程
			// 1. 发送 HTTP 请求到 KGC 服务，获取部分密钥
			url := fmt.Sprintf("http://%s:8080/generateKeys?email=%s&ua=%s", KGC_IP, email, userpubk)
			resp, err := http.Get(url)
			if err != nil {
				log.Fatalf("Failed to request KGC: %v", err)
			}
			defer resp.Body.Close()

			// 2. 解析 KGC 返回的部分私钥和公钥
			var keyResp KeyResponse
			if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
				log.Fatalf("Failed to parse KGC response: %v", err)
			}

			fmt.Println("Received keys from KGC:")
			fmt.Printf("Partial private key: %s\n", keyResp.PartialPrivateKey)
			fmt.Printf("Partial public key: (%s, %s)\n", keyResp.PartialPublicKeyX, keyResp.PartialPublicKeyY)
			fmt.Printf("Curve base point G: (%s, %s)\n", keyResp.Gx, keyResp.Gy)
			fmt.Printf("Curve order N: %s\n", keyResp.N)

			// 3. 解析 KGC 返回的部分私钥和部分公钥
			tA, success := new(big.Int).SetString(keyResp.PartialPrivateKey, 16)
			if !success {
				log.Fatalf("Failed to parse partial private key")
			}

			P_u_X, success := new(big.Int).SetString(keyResp.PartialPublicKeyX, 16)
			if !success {
				log.Fatalf("Failed to parse partial public key X")
			}
			P_u_Y, success := new(big.Int).SetString(keyResp.PartialPublicKeyY, 16)
			if !success {
				log.Fatalf("Failed to parse partial public key Y")
			}

			//fmt.Printf("Time taken to generate tA: %v\n", time.Since(tastartTime))
			el.Stop("TA")

			fmt.Println("Checking partial user keys...")
			core.IsOnCurve(tA, P_u_X, P_u_Y)
			core.IsOnCurveSM2(P_u_X, P_u_Y)

			Nval, success := new(big.Int).SetString(keyResp.N, 16)
			if !success {
				log.Fatalf("Failed to parse N")
			}

			//da_demo := core.Gen_fixed_256bits("acsvfv")
			//d_a_h := core.Hex_to_bytes(da_demo)
			//da_val := new(big.Int).SetBytes(d_a_h)

			el.Start("DA")
			//dAStartTime := time.Now() // 记录计算 dA 的开始时间

			// A3：用户A计算dA=(tA+d'A) mod n；
			dA := new(big.Int).Mod(new(big.Int).Add(tA, dA_), Nval)

			el.Stop("DA")
			//dAElapsedTime := time.Since(dAStartTime) // 记录计算 dA 的时间

			//core.Dbg_print_bigint("tA", tA)
			//core.Dbg_print_bigint("da h", dA_)
			//core.Dbg_print_bigint("da", dA)

			if dA.Sign() == 0 {
				log.Println("dA is 0, returning A1")
				// 这里可以根据需要返回 A1，具体逻辑需要根据你的需求实现
				return nil
			}

			el.Start("dA Public")
			pub_k := core.GeneratePubKeyfromPrivKey(core.BigIntToHexString(dA))
			el.Stop("dA Public")
			//fmt.Printf("Time taken to generate PA: %v\n", elapsedTime2.Nanoseconds())

			bspub := core.Hex_to_bytes(pub_k)
			core.PrintKey("User Full Public Key", bspub)

			fullPriv := dA
			//fmt.Printf("Full private key: %s\n", fullPriv.Text(16))
			bspriv := fullPriv.Bytes()
			//core.PrintKey("User Full Private Key", bspriv)
			//fmt.Printf("DBG: Full Private Key: %X\n", bspriv)
			//priv64 := base64.StdEncoding.EncodeToString(bspriv)
			//fmt.Printf("Private Key BASE64: %s\n", priv64)

			verifyUserKeysByKGC(bspub, email)

			privk_sm2, err := sm2.NewPrivateKey(bspriv)
			if err != nil {
				fmt.Printf("WARN: gen_keypair Cannot convert PrivK string: %s\n", fullPriv.String())
				return nil
			}

			//pub_bs := core.Hex_to_bytes(bspub)
			//PrintKey("Public Key", pub_bs)
			padbs := []byte{0x04}
			padbs = append(padbs, bspub...)
			pk_sm2, err := sm2.NewPublicKey(padbs)
			if err != nil {
				fmt.Printf("WARN: gen_keypair Cannot convert PK string: %s: %v\n",
					pub_k, err)
				return nil
			}

			core.PrintKey("WA X", P_u_X.Bytes())
			core.PrintKey("WA Y", P_u_Y.Bytes())
			core.PrintKey("PK X", pk_sm2.X.Bytes())
			core.PrintKey("PK Y", pk_sm2.Y.Bytes())

			plain := "ABC"
			plainbs := []byte(plain)

			encrypterOpts := sm2.NewPlainEncrypterOpts(sm2.MarshalCompressed, sm2.C1C3C2)
			ciphertext, err := sm2.Encrypt(rand.Reader, pk_sm2, plainbs, encrypterOpts)
			if err != nil {
				fmt.Printf("WARN: encrypt failed %v", err)
			}
			plaintext, err := sm2.Decrypt(privk_sm2, ciphertext)
			if err != nil {
				fmt.Printf("WARN: decrypt failed %v", err)
			}

			fmt.Printf("Verified. Result: %s\n", plaintext)

			return nil
		},
	}

	pubkeyCmd := &cli.Command{
		Name:  "pubkey",
		Usage: "get public key from private key",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "curve", Value: false, DisableDefaultText: true, Usage: "get curve25519 key"},
			&cli.BoolFlag{Name: "sm2", Value: false, DisableDefaultText: true, Usage: "get sm2 key"},
		},
		Action: func(c *cli.Context) error {
			privKey, err := base64.StdEncoding.DecodeString(c.Args().First())
			if err != nil {
				return err
			}
			cipherType := core.ECC_CURVE25519
			if c.Bool("sm2") {
				cipherType = core.ECC_SM2
			}
			e := core.ECDHFromKey(cipherType, privKey)
			if e == nil {
				return fmt.Errorf("invalid input key")
			}
			pub := e.PublicKeyBase64()
			fmt.Println("Public key: ", pub)
			return nil
		},
	}

	// 将命令添加到应用程序
	app.Commands = []*cli.Command{
		runCmd,
		keygenCmd,
		kgcCmd,
		pubkeyCmd,
	}

	// 设置默认的 Action，当没有指定命令时执行 kgc-interact
	app.Action = func(c *cli.Context) error {
		// 调用 kgcCmd 的 Action 方法
		return kgcCmd.Action(c)
	}

	// 运行应用程序
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

type VerifyResponse struct {
	Result string `json:"result"`
}

func verifyUserKeysByKGC(pubk []byte, userid string) {
	pk64 := hex.EncodeToString(pubk)
	//priv64 := hex.EncodeToString(privk)
	url1 := fmt.Sprintf("http://%s:8080/verifyKeys?user=%s&userpk=%s",
		KGC_IP, userid, pk64)
	// 1. 发送 HTTP 请求到 KGC 服务
	resp, err := http.Get(url1)
	if err != nil {
		log.Fatalf("Failed to request verification: %v", err)
	}
	defer resp.Body.Close()

	// 2. 解析 KGC 返回信息
	var keyResp VerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		log.Fatalf("Failed to parse KGC response for verify: %v", err)
	}

	fmt.Printf("Verification result: %s\n", keyResp.Result)
}

func verifyUserKeysByEncrypt(pubk, privk []byte) {
	pkinst, err := sm2.NewPrivateKey(privk)
	if err != nil {
		fmt.Printf("WARN: Cannot generate Priv Key: %x\n", privk)
		return
	}

	pbk := &pkinst.PublicKey

	pbhex := fmt.Sprintf("%x", pubk)
	pub_key := core.Str_to_pk(pbhex)
	if pbk.X.Cmp(pub_key.X) != 0 {
		fmt.Printf("X not same: %x vs %x\n", pbk.X.Bytes(), pub_key.X.Bytes())
	}
	if pbk.Y.Cmp(pub_key.Y) != 0 {
		fmt.Printf("Y not same: %x vs %x\n", pbk.Y.Bytes(), pub_key.Y.Bytes())
	}

	fmt.Printf("Verified for %x and %x\n", privk, pubk)
}

func runApp() error {
	exeFilePath, err := os.Executable()
	if err != nil {
		fmt.Printf("INFO: Cannot find exe %s: %v\n", exeFilePath, err)
		return err
	}
	exeDirPath := filepath.Dir(exeFilePath)
	//fmt.Printf("DBG: Path: %s, File: %s\n", exeDirPath, exeFilePath)

	a := &agent.UdpAgent{}
	err = a.Start(exeDirPath, 4) // log level
	if err != nil {
		fmt.Printf("INFO: Cannot start %s: %v\n", exeDirPath, err)
		return err
	}
	a.StartKnockLoop()

	// react to terminate signals
	termCh := make(chan os.Signal, 1)
	signal.Notify(termCh, syscall.SIGTERM, os.Interrupt, syscall.SIGABRT)

	// block until terminated
	<-termCh
	a.Stop()
	return nil
}
