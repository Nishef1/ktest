package connectiondns

import "testing"

func TestServerlessDNSFailsClosedWithoutLocalRoute(t *testing.T) {
	if _, _, err := MobileResolversWithCustom("serverless", "", ""); err == nil {
		t.Fatal("Serverless resolver leaked without a local proxy")
	}
	if _, _, err := MobilePacketDNSWithCustom("serverless", "", ""); err == nil {
		t.Fatal("Serverless packet DNS leaked without a local proxy")
	}
	if _, _, err := MobileResolversWithCustom("serverless", "127.0.0.1:10808", "8.8.8.8"); err == nil {
		t.Fatal("Serverless resolver accepted custom plaintext DNS")
	}
	if _, _, err := MobilePacketDNSWithCustom("serverless", "127.0.0.1:10808", "8.8.8.8"); err == nil {
		t.Fatal("Serverless packet DNS accepted custom plaintext DNS")
	}
}
