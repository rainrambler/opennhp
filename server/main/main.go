package main

import (
	"crypto/rand"
	"encoding/base64"
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
	"runtime/pprof"
	"strings"
	"syscall"

	"github.com/OpenNHP/opennhp/core"
	"github.com/OpenNHP/opennhp/server"
	"github.com/OpenNHP/opennhp/version"
	_ "github.com/emmansun/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/urfave/cli/v2"
)

// KeyResponse 包含返回给 Server 的部分密钥和椭圆曲线参数
type KeyResponse struct {
	PartialPrivateKey string `json:"partial_private_key"`
	PartialPublicKeyX string `json:"partial_public_key_x"`
	PartialPublicKeyY string `json:"partial_public_key_y"`
	Gx                string `json:"Gx"`
	Gy                string `json:"Gy"`
	N                 string `json:"N"`
}

func to_base64(bs []byte) string {
	return base64.StdEncoding.EncodeToString(bs)
}

func main() {
	app := cli.NewApp()
	app.Name = "nhp-server"
	app.Usage = "server entity for NHP protocol"
	app.Version = version.Version

	runCmd := &cli.Command{
		Name:  "run",
		Usage: "create and run server process for NHP protocol",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "prof", Value: false, DisableDefaultText: true, Usage: "running profiling for the server"},
		},
		Action: func(c *cli.Context) error {
			return runApp(c.Bool("prof"))
		},
	}

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

	// 添加 kgc-interact 命令
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

			cv := sm2.P256Sm2()
			fmt.Printf("DBG: Curve Info: GX=%X, GY=%X, N=%X\n",
				cv.Params().Gx.Bytes(),
				cv.Params().Gy.Bytes(),
				cv.Params().N.Bytes())

			fmt.Printf("DBG Part Priv: %s, Pub X: %s, Y: %s\n",
				to_base64(D_u.Bytes()), to_base64(P_u_X.Bytes()), to_base64(P_u_Y.Bytes()))

			// 4. 生成 Server 的部分私钥和公钥
			x_u := new(big.Int)
			x_u, err = rand.Int(rand.Reader, cv.Params().N) // Server 部分私钥 x_u
			if err != nil {
				log.Fatalf("Failed to generate server partial private key: %v", err)
			}
			X_u, Y_u := cv.ScalarBaseMult(x_u.Bytes()) // Server 部分公钥

			fmt.Printf("Server partial private key (x_u): %s\n", x_u.Text(16))
			fmt.Printf("Server partial public key (X_u, Y_u): (%s, %s)\n", X_u.Text(16), Y_u.Text(16))

			// 5. 合并公钥 (P_u + X_u)
			fullPubX, fullPubY := cv.Add(P_u_X, P_u_Y, X_u, Y_u)
			fmt.Printf("Full public key: (%s, %s)\n", fullPubX.Text(16), fullPubY.Text(16))

			bsx := fullPubX.Bytes()
			bsy := fullPubY.Bytes()
			bspub := bsx
			bspub = append(bspub, bsy...)
			fmt.Printf("DBG: Full Public Key: %X\n", bspub)
			pub64 := base64.StdEncoding.EncodeToString(bspub)
			fmt.Printf("Public Key BASE64: %s\n", pub64)

			// 6. 合并私钥 (D_u + x_u)
			fullPriv := new(big.Int).Add(D_u, x_u)
			fullPriv.Mod(fullPriv, cv.Params().N) // 完整私钥 D_u + x_u
			fmt.Printf("Full private key: %s\n", fullPriv.Text(16))

			bspriv := fullPriv.Bytes()
			fmt.Printf("DBG: Full Private Key: %X\n", bspriv)
			priv64 := base64.StdEncoding.EncodeToString(bspriv)
			fmt.Printf("Private Key BASE64: %s\n", priv64)

			return nil
		},
	}

	// 将命令添加到应用程序
	app.Commands = []*cli.Command{
		runCmd,
		keygenCmd,
		kgcCmd, // 添加 kgc-interact 命令
	}

	// 设置默认的 Action，当没有指定命令时执行 kgc-interact
	app.Action = func(c *cli.Context) error {
		return kgcCmd.Action(c)
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

func runApp(enableProfiling bool) error {
	exeFilePath, err := os.Executable()
	if err != nil {
		return err
	}
	exeDirPath := filepath.Dir(exeFilePath)

	if enableProfiling {
		// Start profiling
		f, err := os.Create(filepath.Join(exeDirPath, "cpu.prf"))
		if err == nil {
			pprof.StartCPUProfile(f)
			defer pprof.StopCPUProfile()
		}
	}

	us := server.UdpServer{}
	err = us.Start(exeDirPath, 4)
	if err != nil {
		return err
	}

	// react to terminate signals
	termCh := make(chan os.Signal, 1)
	signal.Notify(termCh, syscall.SIGTERM, os.Interrupt)

	// block until terminated
	<-termCh
	us.Stop()

	return nil
}
