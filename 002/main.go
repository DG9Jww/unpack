package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/exp/mmap"
)

func main() {
	readerAt, err := mmap.Open("1.png")
	if err != nil {
		fmt.Println(err)
		return
	}
    buf := make([]byte,64)
    _,err = readerAt.ReadAt(buf,0)
    if err != nil {
        fmt.Println(err)
        return
    }
    hexOutput("The first 64 bytes:",buf)


    len := readerAt.Len()
    _,err = readerAt.ReadAt(buf,int64(len-64))
    if err != nil {
        fmt.Println(err)
        return
    }
    hexOutput("The first 64 bytes:",buf)
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
