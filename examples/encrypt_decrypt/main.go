package main

import (
	"github.com/zhangdapeng520/zdpgo_password_file"
)

/*
@Time : 2022/7/8 14:54
@Author : 张大鹏
@File : main.go
@Software: Goland2021.3.1
@Description: 加密文件和解密文件，文件名会发生改变
*/

func main() {
	p := zdpgo_password_file.New()

	filePath := "examples/test1.txt"

	// 先加密
	err := p.EncryptFile(filePath)
	if err != nil {
		panic(err)
	}

	// 再解密
	err = p.DecryptFile(filePath)
	if err != nil {
		panic(err)
	}
}
