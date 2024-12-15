package core

import (
	"fmt"
	"strings"
	"time"

	b64 "encoding/base64"

	"github.com/OpenNHP/opennhp/log"
	"golang.org/x/exp/rand"
)

func Decode(basestr string) []byte {
	uDec, _ := b64.StdEncoding.DecodeString(basestr)
	return uDec
}

func DecodeStr(basestr string) []byte {
	uDec, _ := b64.StdEncoding.DecodeString(basestr)
	return uDec
}

func EncodeToStr(bs []byte) string {
	return b64.StdEncoding.EncodeToString(bs)
}

func PrintKey(keyname string, bs []byte) {
	if len(bs) == 0 {
		fmt.Printf("%s nil\n", keyname)
		log.Debug("%s nil\n", keyname)
		return
	}
	key64 := b64.StdEncoding.EncodeToString(bs)
	fmt.Printf("%s BASE64: [%s] %d Bytes: %X...%X\n",
		keyname, key64, len(bs), bs[:4], bs[len(bs)-4:])

	log.Debug("%s BASE64: [%s] %d Bytes: %X\n", keyname, key64, len(bs), bs)
}

func DecodePrint(basestr string) {
	uDec, _ := b64.StdEncoding.DecodeString(basestr)
	bs := byte2hex(uDec)
	fmt.Printf("Decoded: %s [%d]\n", bs, len(bs))
	//desc := string(uDec)
	//fmt.Printf("Decoded Str: %s [%d]\n", desc, len(desc))
}

func byte2hex(arr []byte) string {
	return fmt.Sprintf("%X", arr)
}

func PrintBytes(desc string, bs []byte) {
	fmt.Printf("%s: %s [%d]\n", desc, bs, len(bs))
	//desc := string(uDec)
	//fmt.Printf("Decoded Str: %s [%d]\n", desc, len(desc))
}

type ElapseLogger struct {
	startTime time.Time
	cur_oper  string
}

func (p *ElapseLogger) Start(oper_name string) {
	if p.cur_oper != "" {
		log.Error("Multi-Timer not supported: %s vs %s\n", oper_name, p.cur_oper)
		return
	}
	p.cur_oper = oper_name
	p.startTime = time.Now()
}

func (p *ElapseLogger) Stop(oper_name string) {
	duration := time.Since(p.startTime)
	if oper_name != p.cur_oper {
		log.Error("Timer not match: %s vs %s\n", oper_name, p.cur_oper)
		return
	}
	fmt.Printf("Timer: %s duration: %v ns\n", p.cur_oper, duration.Nanoseconds())
	//fmt.Printf("Timer: %s duration: %v ns\n", p.cur_oper, duration.Nanoseconds())
	log.Info("Timer: %s duration: %v ns\n", p.cur_oper, duration.Nanoseconds())
	p.cur_oper = ""
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandomString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	for i := 0; i < n; i++ {
		sb.WriteByte(charset[rand.Intn(len(charset))])
	}
	return sb.String()
}
