package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

const (
    BUF_SIZE = 64
)

func main() {

	file, err := os.Open("1.png")
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	buf := make([]byte, BUF_SIZE)
    //前64位数据
	file.Seek(0, os.SEEK_SET)
	file.Read(buf)
    hexOutput("The first 64 byte:",buf)

    //后64位数据
    file.Seek(-64,os.SEEK_END)
	file.Read(buf)
    hexOutput("The first 64 byte:",buf)

}


//输出
func hexOutput(msg string,b []byte) {
    if len(b) == 0 {
        fmt.Println("Error:Buf is null")
        return
    }

    fmt.Printf("%s\n",msg)
    //先byte转16进制，再全部转大写
	encodedStr := strings.ToUpper(hex.EncodeToString(b))
    var n,m int = 0,2
    var x = 0
    for {
        if m > 128 {
            break
        }
        fmt.Printf("%s ",encodedStr[n:m])
        n += 2
        m += 2
        x++
        if x == 8 {
            fmt.Println() 
            x = 0
        }
    }
    fmt.Println()
}
