package login

import (
	"github.com/haveachin/infrared/protocol"
)

const ServerBoundLoginStartPacketID byte = 0x00

type ServerLoginStart struct {
	Name protocol.String
}

type ServerLoginStartNew struct {
	Name       protocol.String
	HasSigData protocol.Boolean
	Timestamp  protocol.Long
	PublicKey  protocol.ByteArray
	Signature  protocol.ByteArray
}

func UnmarshalServerBoundLoginStart(packet protocol.Packet) (ServerLoginStart, ServerLoginStartNew, error) {
	var pk ServerLoginStart
	var pknew ServerLoginStartNew

	if packet.ID != ServerBoundLoginStartPacketID {
		return pk, pknew, protocol.ErrInvalidPacketID
	}

	if err := packet.Scan(&pk.Name); err != nil {
		return pk, pknew, err
	}

	if err := packet.Scan(
		&pknew.Name,
		&pknew.HasSigData,
		&pknew.Timestamp,
		&pknew.PublicKey,
		&pknew.Signature,
	); err != nil {
		return pk, pknew, nil
	}

	return pk, pknew, nil
}
