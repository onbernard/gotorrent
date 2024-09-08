package main

import (
	"testing"
)

func TestParseExactTopic(t *testing.T) {
	// BitTorrent info hash v1 (BTIH)
	btih_1 := "urn:btih:0123456789abcdef0123456789abcdef01234567"
	btih_2 := "urn:btih:ED0DA850C273E3E15A819BDCBBF418BC85107EC8"
	// BitTorrent info hash v2 (BTMH)
	btmh_1 := "urn:btmh:1220e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// eDonkey2000 (ED2K)
	ed2k_1 := "urn:ed2k:3a3c3ba2f5c4b7093b4c9a7f620f43c1"
	ed2k_2 := "urn:ed2k:fcf5be43ebf404e1b893ad9e28f7d1be"
	// Tiger Tree Hash (TTH)
	tth_1 := "urn:tree:tiger:2A0B8D5245F8E6F24C5038C9DD3D6C4E5E46709E"
	// Secure Hash Algorithm 1 (SHA-1)
	sha1_1 := "urn:sha1:3I4L5E2X5JGA5YL62ZMZSGMN5IVDMJQZ"
	// Secure Hash Algorithm 256 (SHA-256)
	sha256_1 := "urn:sha256:49d8b9b3ed9aead5b0316b5e4ac30547e87040543b340bf4fa7f8500fdd533d1"
	// Secure Hash Algorithm 512 (SHA-512)
	sha512_1 := "urn:sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	// Message Digest 5
	md5_1 := "urn:md5:098f6bcd4621d373cade4e832627b4f6"
	// CRC32
	crc32_1 := "urn:crc32:81dc9bdb52d04dc20036dbd8313ed055s"
	// BitPrint (SHA1 and Tiger combination)
	bitprint_1 := "urn:bitprint:QFGY2JMK55V4PJJWFCHVUJ6HDN74CSQE.2A0B8D5245F8E6F24C5038C9DD3D6C4E5E46709E"
	// Advanced Intelligent Corruption Handler (AICH)
	aich_1 := "urn:aich:YNCKHTQCWBTRNJIV4WNAE52SJUQCZO5C"
	// Kazaa hash
	kzhash_1 := "urn:kzhash:4a456aabae1179be9861ebef6d9375b3f98a2c40"
	// Kademlia (Kad)
	kad_1 := "urn:kad:4a456aabae1179be9861ebef6d9375b3f98a2c40"
	//
	xtList := [...]string{btih_1, btih_2, btmh_1, ed2k_1, ed2k_2, tth_1, sha1_1, sha256_1, sha512_1, md5_1, crc32_1, bitprint_1, aich_1, kzhash_1, kad_1}
	for _, xt := range xtList {
		parsedXT, err := ParseExactTopic(xt)
		if err != nil {
			t.Errorf("failed to parse %v", xt)
		} else {
			t.Logf("%+v", parsedXT)
		}
	}
}

func TestParseMagnetLink(t *testing.T) {
	magnetURL_1 := "magnet:?xt=urn:btih:ED0DA850C273E3E15A819BDCBBF418BC85107EC8&dn=Dune+%282021%29+%5B1080p%5D+%5BWEBRip%5D&tr=http%3A%2F%2Fp4p.arenabg.com%3A1337%2Fannounce&tr=udp%3A%2F%2F47.ip-51-68-199.eu%3A6969%2Fannounce&tr=udp%3A%2F%2F9.rarbg.me%3A2780%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2710%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2730%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2920%2Fannounce&tr=udp%3A%2F%2Fopen.stealth.si%3A80%2Fannounce&tr=udp%3A%2F%2Fopentracker.i2p.rocks%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.dler.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.tiny-vps.com%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.torrent.eu.org%3A451%2Fannounce"
	magnet_1, err := ParseMagnetLink(magnetURL_1)
	if err != nil {
		t.Fatalf("error parsing magnet url: %v", err)
	}
	t.Logf("%+v", *magnet_1)
	magnetURL_2 := "magnet:?xt=urn:btih:<hash1>&xt.1=urn:btih:<hash2>&xt.2=urn:btih:<hash3>&dn=<file_name>&xl=4242&tr=<tracker_url1>&tr=<tracker_url2>"
	magnet, err := ParseMagnetLink(magnetURL_2)
	if err != nil {
		t.Fatalf("error parsing magnet url: %v", err)
	}
	if magnet.ExactTopic.hashType != BTIH {
		t.Errorf("expected btih, got %v", magnet.ExactTopic.hashType.String())
	}
	if magnet.ExactTopic.hash != `<hash1>` {
		t.Errorf("expected <hash1>, got %v", magnet.ExactTopic.hash)
	}
	if magnet.ExactLength != 4242 {
		t.Errorf("expected 4242, got %v", magnet.ExactLength)
	}
	t.Logf("%+v", *magnet)
}

func TestMakeConnectionRequest(t *testing.T) {
	// request, transactionID := makeConnectionRequest()
	// buf := [16]byte{
	// 	0, 0, 4, 23, 39, 16, 25, 128,
	// 	0x00, 0x00, 0x00, 0x00,
	// }
	// binary.BigEndian.PutUint32(buf[12:], transactionID)
	// if request != buf {
	// 	t.Error("unexpected connection request structure\n", request, "\n", buf)
	// }
}

func TestParseConnectionnResponse(t *testing.T) {
	// buf := [16]byte{
	// 	0, 0, 0, 0,
	// 	0, 0, 0, 42,
	// 	0, 0, 0, 0, 0, 0, 0, 42,
	// }
	// connectionResponse, err := parseConnectionResponse(42, buf)
	// if connectionResponse == nil {
	// 	t.Fatal("error parsing connection response", err)
	// }
	// expectedConnectionResponse := &ConnectionResponse{
	// 	action:        0,
	// 	transactionID: 42,
	// 	connectionID:  42,
	// }
	// if *connectionResponse != *expectedConnectionResponse {
	// 	t.Error("unexpected connection response structure", expectedConnectionResponse, connectionResponse)
	// }
}

func TestMakeAnnounceRequest(t *testing.T) {
	// request, transactionID, key := makeAnnounceRequest(42, "ED0DA850C273E3E15A819BDCBBF418BC85107EC8", "GOTORRENT-6969696969")
	// buf := [98]byte{
	// 	0, 0, 0, 0, 0, 0, 0, 42, // Connection ID
	// 	0, 0, 0, 1, // Action
	// 	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // info_hash
	// 	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Peer ID
	// 	0, 0, 0, 0, 0, 0, 0, 0, // Downloaded
	// 	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Left
	// 	0, 0, 0, 0, 0, 0, 0, 0, // Uploaded
	// 	0, 0, 0, 2, // Event
	// 	0, 0, 0, 0, // IP address
	// 	0, 0, 0, 0, // Key
	// 	0xFF, 0xFF, 0xFF, 0xFF, // Num want
	// 	0x00, 0x00, // Port
	// }
	// binary.BigEndian.PutUint32(buf[12:], transactionID)
	// copy(buf[16:], []byte("ED0DA850C273E3E15A819BDCBBF418BC85107EC8"))
	// copy(buf[36:], []byte("GOTORRENT-6969696969"))
	// binary.BigEndian.PutUint32(buf[88:], key)

}
