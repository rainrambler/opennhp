package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/OpenNHP/opennhp/KGC" // 导入 KGC 包
	"github.com/OpenNHP/opennhp/core"
)

// KeyResponse 包含返回给 Agent 的部分密钥和椭圆曲线参数
type KeyResponse struct {
	PartialPrivateKey string `json:"partial_private_key"`
	PartialPublicKeyX string `json:"partial_public_key_x"`
	PartialPublicKeyY string `json:"partial_public_key_y"`
	Gx                string `json:"Gx"`
	Gy                string `json:"Gy"`
	N                 string `json:"N"`
}

var kgc_inst *KGC.KGC2

// 处理 /generateKeys 请求，生成部分密钥
func handleKeyRequest(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}

	uastr := r.URL.Query().Get("ua")
	if email == "" {
		http.Error(w, "user generated public param is required", http.StatusBadRequest)
		return
	}

	// 测量生成主密钥对的时间
	var el core.ElapseLogger
	el.Start("KGC Master Key")
	//startTime := time.Now() // 记录开始时间

	kgc_inst = new(KGC.KGC2)
	//kgcinst.LoadFixed()

	// 生成 KGC 主密钥对
	kgc_inst.InitRandMasterKeyPair()
	//fmt.Println("KGC Private Key:", kgcPrivateKey)
	//fmt.Println("KGC Public Key:", kgcPublicKey)

	// 计算时间差
	//generationDuration := time.Since(startTime)                   // 记录结束时间
	//fmt.Println("kgc主密钥对生成时间:", generationDuration.Nanoseconds()) // 输出生成时间
	el.Stop("KGC Master Key")

	//pubfull := []byte{}
	//pubfull = append(pubfull, kgcPublicKey.X.Bytes()...)
	//pubfull = append(pubfull, kgcPublicKey.Y.Bytes()...)
	//core.PrintKey("KGC Pub", pubfull)
	//core.PrintKey("KGC Priv", kgcPrivateKey.D.Bytes())

	// 用户信息
	userID := email
	tA, wa := kgc_inst.GenerateKGCPartialKey(userID, uastr)
	xstr, ystr := core.Get_x_y(wa)

	// 椭圆曲线的基点 G
	Gx, Gy, N := core.GetSM2CurveParams()

	// 构建 JSON 响应
	response := KeyResponse{
		PartialPrivateKey: tA.Text(16),
		PartialPublicKeyX: xstr,
		PartialPublicKeyY: ystr,
		Gx:                Gx.Text(16),
		Gy:                Gy.Text(16),
		N:                 N.Text(16),
	}

	// 设置响应头并返回 JSON 数据
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// 处理 /verifyKeys 请求，校验密钥
// Bad practice (Send Private key), only for demo
func verifyKeyRequest(w http.ResponseWriter, r *http.Request) {
	userpk := r.URL.Query().Get("userpk")
	if userpk == "" {
		http.Error(w, "User Public Key is required", http.StatusBadRequest)
		return
	}

	userID := r.URL.Query().Get("user")
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	res := kgc_inst.VerifyUserKey(userpk, userID, len(userID))

	resstr := ""
	if res {
		resstr = "Verified"
	} else {
		resstr = "Failed"
	}
	response := VerifyResponse{
		Result: resstr,
	}

	// 设置响应头并返回 JSON 数据
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

type VerifyResponse struct {
	Result string `json:"result"`
}

func main() {
	// 设置 /generateKeys 路由
	http.HandleFunc("/generateKeys", handleKeyRequest)
	http.HandleFunc("/verifyKeys", verifyKeyRequest)

	// 启动 HTTP 服务
	fmt.Println("KGC HTTP server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
