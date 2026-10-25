package capture

import "context"

// PacketSensor collects packets and returns a summary of the traffic.
type PacketSensor interface {
	Collect(ctx context.Context, emit func(PacketEvent)) (PacketSummary, error)
}

// SocketSensor collects a snapshot of open sockets.
type SocketSensor interface {
	Collect(ctx context.Context, emit func(SocketEvent)) (SocketSummary, error)
}
