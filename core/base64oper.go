package core

import (
	"fmt"

	b64 "encoding/base64"

	"github.com/OpenNHP/opennhp/log"
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
