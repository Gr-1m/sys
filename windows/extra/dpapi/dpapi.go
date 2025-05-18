package dpapi

import (
	"encoding/base64"
	wincall "golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *dataBlob) toByteArray() []byte {
	d := make([]byte, b.cbData)
	/* #nosec# G103 */
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func (b *dataBlob) zeroMemory() {
	zeros := make([]byte, b.cbData)
	/* #nosec# G103 */
	copy((*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:], zeros)
}

func (b *dataBlob) free() error {
	/* #nosec# G103 */
	_, err := syscall.LocalFree(syscall.Handle(unsafe.Pointer(b.pbData)))
	if err != nil {
		return Wrap(err, "localfree")
	}

	return nil
}

// Encrypt a string value to a base64 string
func Encrypt(secret string) (string, error) {
	return encrypt(secret, "", wincall.CRYPTPROTECT_UI_FORBIDDEN)
}

func EncryptEntropy(secret, entropy string) (string, error) {
	return encrypt(secret, entropy, wincall.CRYPTPROTECT_UI_FORBIDDEN)
}

func encrypt(secret, entropy string, cf uint32) (string, error) {
	var result string
	var b []byte
	b, err := encryptBytes([]byte(secret), []byte(entropy), cf)
	if err != nil {
		return result, Wrap(err, "encryptbytes")
	}
	result = base64.StdEncoding.EncodeToString(b)
	return result, nil
}

// EncryptBytes encrypts a byte array and returns a byte array
func EncryptBytes(data []byte) ([]byte, error) {
	return encryptBytes(data, nil, wincall.CRYPTPROTECT_UI_FORBIDDEN)
}

func EncryptBytesEntropy(data, entropy []byte) ([]byte, error) {
	return encryptBytes(data, entropy, wincall.CRYPTPROTECT_UI_FORBIDDEN)
}

func encryptBytes(data []byte, entropy []byte, cf uint32) ([]byte, error) {
	var (
		outblob dataBlob
		r       uintptr
		err     error
	)

	if len(entropy) > 0 {
		/* #nosec# G103 */
		r, _, err = wincall.CryptProtectData(uintptr(unsafe.Pointer(newBlob(data))), 0, uintptr(unsafe.Pointer(newBlob(entropy))), 0, 0, uintptr(cf), uintptr(unsafe.Pointer(&outblob)))
	} else {
		/* #nosec# G103 */
		r, _, err = wincall.CryptProtectData(uintptr(unsafe.Pointer(newBlob(data))), 0, 0, 0, 0, uintptr(cf), uintptr(unsafe.Pointer(&outblob)))
	}
	if r == 0 {
		return nil, Wrap(err, "procencryptdata")
	}

	enc := outblob.toByteArray()
	return enc, outblob.free()
}

// EncryptBytesMachineLocal encrypts a byte array and returns a byte array and associates the data
// encrypted with the current computer instead of with an individual user.
func EncryptBytesMachineLocal(data []byte) ([]byte, error) {
	return encryptBytes(data, nil, wincall.CRYPTPROTECT_UI_FORBIDDEN|wincall.CRYPTPROTECT_LOCAL_MACHINE)
}

func EncryptBytesMachineLocalEntropy(data, entropy []byte) ([]byte, error) {
	return encryptBytes(data, entropy, wincall.CRYPTPROTECT_UI_FORBIDDEN|wincall.CRYPTPROTECT_LOCAL_MACHINE)
}

// EncryptMachineLocal a string value to a base64 string and associates the data encrypted with the
// current computer instead of with an individual user.
func EncryptMachineLocal(secret string) (string, error) {
	return encrypt(secret, "", wincall.CRYPTPROTECT_UI_FORBIDDEN|wincall.CRYPTPROTECT_LOCAL_MACHINE)
}

func EncryptMachineLocalEntropy(secret, entropy string) (string, error) {
	return encrypt(secret, entropy, wincall.CRYPTPROTECT_UI_FORBIDDEN|wincall.CRYPTPROTECT_LOCAL_MACHINE)
}

// DecryptBytes decrypts a byte array returning a byte array
func decryptBytes(data, entropy []byte, cf uint32) ([]byte, error) {
	var (
		outblob wincall.DataBlob
		r       uintptr
		err     error
	)
	if len(entropy) > 0 {
		/* #nosec# G103 */
		r, _, err = wincall.CryptUnprotectData(uintptr(unsafe.Pointer(newBlob(data))), 0, uintptr(unsafe.Pointer(newBlob(entropy))), 0, 0, uintptr(cf), uintptr(unsafe.Pointer(&outblob)))
	} else {
		/* #nosec# G103 */
		r, _, err = procDecryptData.Call(uintptr(unsafe.Pointer(newBlob(data))), 0, 0, 0, 0, uintptr(cf), uintptr(unsafe.Pointer(&outblob)))
	}
	if r == 0 {
		return nil, Wrap(err, "procdecryptdata")
	}

	dec := outblob.toByteArray()
	outblob.zeroMemory()
	return dec, outblob.free()
}

// Decrypt a string to a string
func Decrypt(data string) (string, error) {
	return DecryptEntropy(data, "")
}

// EncryptBytes encrypts a byte array and returns a byte array
func DecryptBytes(data []byte) ([]byte, error) {
	return decryptBytes(data, nil, wincall.CRYPTPROTECT_UI_FORBIDDEN)
}

func DecryptBytesEntropy(data, entropy []byte) ([]byte, error) {
	return decryptBytes(data, entropy, wincall.CRYPTPROTECT_UI_FORBIDDEN)
}

func DecryptEntropy(data, entropy string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", Wrap(err, "decodestring")
	}

	b, err := decryptBytes(raw, []byte(entropy), wincall.CRYPTPROTECT_UI_FORBIDDEN)
	if err != nil {
		return "", Wrap(err, "decryptbytes")
	}
	return string(b), nil
}
