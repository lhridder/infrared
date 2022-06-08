package login

import (
	"github.com/haveachin/infrared/protocol"
)

const ServerBoundEncryptionResponsePacketID = 0x01

type ServerBoundEncryptionResponse struct {
	SharedSecret protocol.ByteArray
	VerifyToken  protocol.ByteArray
}

type ServerBoundEncryptionResponseNew struct {
	SharedSecret protocol.ByteArray
	Salt         protocol.Long
	Signature    protocol.ByteArray
}

func (pk ServerBoundEncryptionResponse) Marshal() protocol.Packet {
	return protocol.MarshalPacket(
		ServerBoundEncryptionResponsePacketID,
		pk.SharedSecret,
		pk.VerifyToken,
	)
}

func UnmarshalServerBoundEncryptionResponse(packet protocol.Packet, protocolVersion protocol.VarInt) (ServerBoundEncryptionResponse, ServerBoundEncryptionResponseNew, error) {
	var pk ServerBoundEncryptionResponse
	var pknew ServerBoundEncryptionResponseNew

	if packet.ID != ServerBoundEncryptionResponsePacketID {
		return pk, pknew, protocol.ErrInvalidPacketID
	}

	if protocolVersion >= 759 {
		err := packet.Scan(
			&pknew.SharedSecret,
			&pknew.Salt,
			&pknew.Signature,
		)
		if err != nil {
			return pk, pknew, err
		}
	} else {
		err := packet.Scan(
			&pk.SharedSecret,
			&pk.VerifyToken,
		)
		if err != nil {
			return pk, pknew, err
		}
	}

	return pk, pknew, nil
}
