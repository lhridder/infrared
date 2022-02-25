package login

import "github.com/haveachin/infrared/protocol"

const ClientBoundLoginSuccessPacketID byte = 0x02

type ClientBoundLoginSuccess struct {
	UUID     protocol.UUID
	Username protocol.String
}

func (pk ClientBoundLoginSuccess) Marshal() protocol.Packet {
	return protocol.MarshalPacket(
		ClientBoundLoginSuccessPacketID,
		pk.UUID,
		pk.Username,
	)
}
