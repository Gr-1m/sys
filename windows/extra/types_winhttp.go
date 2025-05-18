package extra

import "go/types"

const (
	// WinHttpOpen dwAccessType values (also for WINHTTP_PROXY_INFO::dwAccessType)
	WINHTTP_ACCESS_TYPE_DEFAULT_PROXY   = 0
	WINHTTP_ACCESS_TYPE_NO_PROXY        = 1
	WINHTTP_ACCESS_TYPE_NAMED_PROXY     = 3
	WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4

	// WinHttpOpenRequest prettifers for optional parameters
	WINHTTP_NO_REFERER           = ""
	WINHTTP_DEFAULT_ACCEPT_TYPES = ""

	// Flags for dwAutoDetectFlags
	WINHTTP_AUTO_DETECT_TYPE_DHCP  = 0x00000001
	WINHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002
)

// WinHttpOpen prettifiers for optional parameters
type (
	WINHTTP_NO_CLIENT_CERT_CONTEXT = types.Nil
)

type WinHttpCurrUserIEProxyConfig struct {
	FbAutoDetect      bool
	LpszAutoConfigUrl *uint16
	LpszProxy         *uint16
	LpszProxyBypass   *uint16
}
