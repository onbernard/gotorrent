package tracker

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type ExactTopicHashType int

const (
	BTIH ExactTopicHashType = iota
	BTMH
	EDonkey
	TigerTree
	SHA1
	SHA256
	SHA512
	MD5
	CRC32
	BitPrint
	AICH
	Kazaa
	Kademlia
)

func (t ExactTopicHashType) String() string {
	return [...]string{
		"btih", "btmh", "ed2k", "tree:tiger", "sha1", "sha256", "sha512", "md5", "crc32", "bitprint", "aich", "kzhash", "kad",
	}[t]
}

type ExactTopic struct {
	HashType ExactTopicHashType
	Hash     string
}

type MagnetLink struct {
	ExactTopic       ExactTopic
	ExactTopicGroup  []ExactTopic
	DisplayName      string
	ExactLength      uint64
	Trackers         []string
	WebSeed          string
	AcceptableSource []string
	ExactSource      []string
	KeywordTopic     []string
	ManifestTopic    []string
	SelectOnly       string
	Peer             []string
	// xs          string
	// as          string
}

func ParseExactTopic(xt string) (*ExactTopic, error) {
	outp := ExactTopic{}
	xtParts := strings.Split(xt, ":")
	if len(xtParts) < 3 {
		return nil, fmt.Errorf("unexpected xt format: %v", xt)
	}
	if xtParts[0] != `urn` {
		return nil, fmt.Errorf("unexpected xt format: %v", xt)
	}
	switch xtParts[1] {
	case `btih`:
		outp.HashType = BTIH
		outp.Hash = xtParts[2]
	case `btmh`:
		outp.HashType = BTMH
		outp.Hash = xtParts[2]
	case `ed2k`:
		outp.HashType = EDonkey
		outp.Hash = xtParts[2]
	case `tree`:
		if len(xtParts) < 4 {
			return nil, fmt.Errorf("unexpected xt format: %v", xt)
		}
		outp.HashType = TigerTree
		outp.Hash = xtParts[3]
	case `sha1`:
		outp.HashType = SHA1
		outp.Hash = xtParts[2]
	case `sha256`:
		outp.HashType = SHA256
		outp.Hash = xtParts[2]
	case `sha512`:
		outp.HashType = SHA512
		outp.Hash = xtParts[2]
	case `md5`:
		outp.HashType = MD5
		outp.Hash = xtParts[2]
	case `crc32`:
		outp.HashType = CRC32
		outp.Hash = xtParts[2]
	case `bitprint`:
		outp.HashType = BitPrint
		outp.Hash = xtParts[2]
	case `aich`:
		outp.HashType = AICH
		outp.Hash = xtParts[2]
	case `kzhash`:
		outp.HashType = Kazaa
		outp.Hash = xtParts[2]
	case `kad`:
		outp.HashType = Kademlia
		outp.Hash = xtParts[2]
	}
	return &outp, nil
}

func ParseMagnetLink(s string) (*MagnetLink, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	outp := MagnetLink{}
	queries := u.Query()
	// xt
	xtList, exists := queries[`xt`]
	if exists {
		if len(xtList) != 1 {
			return nil, fmt.Errorf("unexpected number of xt fields: %v", len(xtList))
		}
		parsedXT, err := ParseExactTopic(xtList[0])
		if err != nil {
			return nil, err
		}
		outp.ExactTopic = *parsedXT
	}
	for i := 1; ; i++ {
		xtList, exists = queries[`xt.`+strconv.Itoa(i)]
		if exists {
			if len(xtList) != 1 {
				return nil, fmt.Errorf("unexpected number of xt fields: %v", len(xtList))
			}
			parsedXT, err := ParseExactTopic(xtList[0])
			if err != nil {
				return nil, err
			}
			outp.ExactTopicGroup = append(outp.ExactTopicGroup, *parsedXT)
		} else {
			break
		}
	}
	// dn
	dnList, exists := queries[`dn`]
	if exists {
		if len(dnList) != 1 {
			return nil, fmt.Errorf("unexpected number of dn fields: %v", len(dnList))
		}
		outp.DisplayName = dnList[0]
	}
	// xl
	xlList, exists := queries[`xl`]
	if exists {
		if len(xlList) != 1 {
			return nil, fmt.Errorf("unexpected number of xl fields: %v", len(xlList))
		}
		i, err := strconv.Atoi(xlList[0])
		if err != nil {
			return nil, fmt.Errorf("unexpected xl format: %v", xlList[0])
		}
		outp.ExactLength = uint64(i)
	}
	// tr
	trList, exists := queries[`tr`]
	if exists {
		outp.Trackers = trList
	}
	// ws
	wsList, exists := queries[`ws`]
	if exists {
		if len(wsList) != 1 {
			return nil, fmt.Errorf("unexpected number of ws fields: %v", len(wsList))
		}
		outp.WebSeed = wsList[0]
	}
	// as
	asList, exists := queries[`as`]
	if exists {
		outp.AcceptableSource = asList
	}
	// xs
	xsList, exists := queries[`xs`]
	if exists {
		outp.ExactSource = xsList
	}
	// kt
	ktList, exists := queries[`kt`]
	if exists {
		outp.KeywordTopic = ktList
	}
	// mt
	mtList, exists := queries[`mt`]
	if exists {
		outp.ManifestTopic = mtList
	}
	// so
	soList, exists := queries[`so`]
	if exists {
		if len(soList) != 1 {
			return nil, fmt.Errorf("unexpected number of so fields: %v", len(soList))
		}
		outp.SelectOnly = soList[0]
	}
	// x.pe
	xpeList, exists := queries[`x.pe`]
	if exists {
		outp.Peer = xpeList
	}
	return &outp, nil
}
