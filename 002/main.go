package main

import (
	"fmt"
	"os"

	"github.com/edsrzf/mmap-go"
	"golang.org/x/sys/unix"
)

func main() {
	file, err := os.OpenFile("1.png", os.O_RDONLY, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}
    
	mmap.Map(file, mmap.RDONLY, unix.SHARED)

}
