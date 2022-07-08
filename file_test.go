package zdpgo_password_file

import (
	"testing"
)

// 测试获取加密名称
func TestPassword_getEncryptFileName(t *testing.T) {
	p := New()
	files := []string{
		"a/b/c/d/ttt.txt",
		"c:\\a\\b\\c\\ttt.txt",
	}
	for _, file := range files {
		_, _, err := p.GetEncryptFileName(file)
		if err != nil {
			panic(err)
		}
	}
}

// 测试加密文件，但是不改变文件名称
func TestPassword_EncryptFileNoChangeName(t *testing.T) {
	p := New()
	files := []string{
		"examples/test1.txt",
	}
	for _, file := range files {
		err := p.EncryptFileNoChangeName(file)
		if err != nil {
			panic(err)
		}
	}
}

// 测试解密文件，且不改变文件名称
func TestPassword_DecryptFileNoChangeName(t *testing.T) {
	p := New()

	// 先加密
	filePath := "examples/test2.txt"
	err := p.EncryptFileNoChangeName(filePath)
	if err != nil {
		panic(err)
	}

	// 再解密
	err = p.DecryptFileNoChangeName(filePath)
	if err != nil {
		panic(err)
	}
}

func TestPassword_DecryptFile(t *testing.T) {
	p := New()

	filePath := "examples/test2.txt"

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
