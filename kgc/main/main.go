package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/OpenNHP/opennhp/KGC" // 导入 KGC 包
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

// 处理 /generateKeys 请求，生成部分密钥
func handleKeyRequest(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}

	// 生成 KGC 主密钥对
	kgcPrivateKey, kgcPublicKey := KGC.GetFixedMasterKeyPair()
	//fmt.Println("KGC Private Key:", kgcPrivateKey)
	//fmt.Println("KGC Public Key:", kgcPublicKey)

	// 用户信息
	userID := email
	entlenA := len(userID)

	// 生成用户的部分密钥
	waPublicKey, tA := KGC.GenerateKGCPartialKey(userID, entlenA, kgcPrivateKey, kgcPublicKey)
	fmt.Println("WA Public Key:", waPublicKey)
	fmt.Println("tA:", tA)

	// 计算 HA
	ha := KGC.CalculateHA(userID, entlenA, waPublicKey.X, waPublicKey.Y)
	fmt.Println("HA:", ha)

	// 椭圆曲线的基点 G
	Gx, Gy, N := KGC.GetCurveParams()

	// 构建 JSON 响应
	response := KeyResponse{
		PartialPrivateKey: tA.Text(16),
		PartialPublicKeyX: waPublicKey.X.Text(16),
		PartialPublicKeyY: waPublicKey.Y.Text(16),
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

	userprivk := r.URL.Query().Get("userprivk")
	if userprivk == "" {
		http.Error(w, "User Private Key is required", http.StatusBadRequest)
		return
	}

	userID := r.URL.Query().Get("user")
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	res := KGC.VerifyUserKey(userprivk, userpk, userID, len(userID))

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
