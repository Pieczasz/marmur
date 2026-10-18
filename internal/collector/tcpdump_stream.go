package collector

import "io"

func readPackets(r io.Reader, emit func(PacketEvent)) (skipped int, err error) {

}
