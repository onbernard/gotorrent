package main

import (
	"sync"

	"github.com/onbernard/gotorrent/internal/tracker"
	log "github.com/sirupsen/logrus"
)

func main() {
	magnetURL := "magnet:?xt=urn:btih:4ED8248102AC7DA2578B106C95B708B2648F176F&dn=DeadPool+and+Wolverine+2024+1080p+V1+Clean+HDTS+H264+COLLECTiVE&tr=http%3A%2F%2Fp4p.arenabg.com%3A1337%2Fannounce&tr=udp%3A%2F%2F47.ip-51-68-199.eu%3A6969%2Fannounce&tr=udp%3A%2F%2F9.rarbg.me%3A2780%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2710%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2730%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2920%2Fannounce&tr=udp%3A%2F%2Fopen.stealth.si%3A80%2Fannounce&tr=udp%3A%2F%2Fopentracker.i2p.rocks%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.dler.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.tiny-vps.com%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.torrent.eu.org%3A451%2Fannounce"

	magnet, err := tracker.ParseMagnetLink(magnetURL)
	if err != nil {
		panic(err)
	}
	log.SetLevel(log.DebugLevel)
	var wg sync.WaitGroup

	for _, tr := range magnet.Trackers {
		wg.Add(1)
		go func(trackerURL string, hash string) {
			defer wg.Done()
			outp, err := tracker.RequestUDPTracker(trackerURL, hash)
			if err != nil {
				log.Error(trackerURL, "\t\t", err)
			} else {
				log.Info(trackerURL, "\t\t", len(outp.Peers))
			}
		}(tr, magnet.ExactTopic.Hash)
	}
	wg.Wait()
}
