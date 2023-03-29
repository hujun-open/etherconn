package etherconn

func getNumRecvRoutine(relay PacketRelay) int {
	switch xrelay := relay.(type) {
	case *XDPRelay:
		return xrelay.NumSocket()
	default:
		return 1
	}

}
