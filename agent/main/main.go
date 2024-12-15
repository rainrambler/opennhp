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
	_ "github.com/emmansun/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm2"
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
			fmt.Print("Enter your email: ")
			fmt.Scanln(&email)

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

			// 继续与 KGC 交互的流程
			// 1. 发送 HTTP 请求到 KGC 服务，获取部分密钥
			resp, err := http.Get(fmt.Sprintf("http://localhost:8080/generateKeys?email=%s", email))
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
			D_u, success := new(big.Int).SetString(keyResp.PartialPrivateKey, 16)
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

			fmt.Println("Checking partial user keys...")
			core.IsOnCurve(D_u, P_u_X, P_u_Y)
			core.IsOnCurveSM2(P_u_X, P_u_Y)

			//curve1 := sm2.P256()
			Nval, success := new(big.Int).SetString(keyResp.N, 16)
			if !success {
				log.Fatalf("Failed to parse N")
			}
			//Nval := keyResp.N

			// 3. 产生随机数 d'A ∈ [1, n−1]
			dA_, err := rand.Int(rand.Reader, Nval)
			if err != nil {
				log.Fatalf("Failed to generate random d'A: %v", err)
			}

			// 4. 计算 UA = [d'A]G
			curve1 := sm2.P256Sm2()
			UAx, UAy := curve1.ScalarBaseMult(dA_.Bytes())

			// 这里将 UAx 和 UAy 打印出来以避免未使用的错误
			log.Printf("UA coordinates: (%s, %s)", UAx.String(), UAy.String())

			// 5. 提交 IDA 和 UA 给 KGC
			//waPublicKey, tA := KGC.GenerateKGCPartialKey(userID, entlenA, kgcPrivateKey, kgcPublicKey)
			waPublicKey := &sm2.PublicKey{
				Curve: curve1,
				X:     P_u_X,
				Y:     P_u_Y,
			}
			tA := D_u

			// 6. 计算 dA = (tA + d'A) mod n
			dA := new(big.Int).Mod(new(big.Int).Add(tA, dA_), Nval)

			if dA.Sign() == 0 {
				log.Println("dA is 0, returning A1")
				// 这里可以根据需要返回 A1，具体逻辑需要根据你的需求实现
				return nil
			}

			// 7. 返回 dA 和 WA
			//return dA, waPublicKey
			fmt.Println("Checking user keys...")
			core.IsOnCurve(dA, waPublicKey.X, waPublicKey.Y)
			core.IsOnCurveSM2(waPublicKey.X, waPublicKey.Y)

			bsx := waPublicKey.X.Bytes()
			bsy := waPublicKey.Y.Bytes()
			bspub := bsx
			bspub = append(bspub, bsy...)
			core.PrintKey("User Full Public Key", bspub)
			//fmt.Printf("DBG: Full Public Key: %X\n", bspub)
			//pub64 := base64.StdEncoding.EncodeToString(bspub)
			//fmt.Printf("Public Key BASE64: %s\n", pub64)

			// 6. 合并私钥 (D_u + x_u)
			fullPriv := dA
			//fmt.Printf("Full private key: %s\n", fullPriv.Text(16))
			bspriv := fullPriv.Bytes()
			core.PrintKey("User Full Private Key", bspriv)
			//fmt.Printf("DBG: Full Private Key: %X\n", bspriv)
			//priv64 := base64.StdEncoding.EncodeToString(bspriv)
			//fmt.Printf("Private Key BASE64: %s\n", priv64)

			verifyUserKeys(bspub, bspriv, email)

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

func verifyUserKeys(pubk, privk []byte, userid string) {
	pk64 := hex.EncodeToString(pubk)
	priv64 := hex.EncodeToString(privk)
	url1 := fmt.Sprintf("http://localhost:8080/verifyKeys?user=%s&userpk=%s&userprivk=%s",
		userid, pk64, priv64)
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

func runApp() error {
	exeFilePath, err := os.Executable()
	if err != nil {
		fmt.Printf("INFO: Cannot find exe %s: %v\n", exeFilePath, err)
		return err
	}
	exeDirPath := filepath.Dir(exeFilePath)
	fmt.Printf("DBG: Path: %s, File: %s\n", exeDirPath, exeFilePath)

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
