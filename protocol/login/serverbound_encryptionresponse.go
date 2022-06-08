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
	EncryptedSecretKey protocol.ByteArray
	UseVerifyToken     protocol.Boolean
	VerifyToken        protocol.ByteArray
	Salt               protocol.Long
	Signature          protocol.ByteArray
}

func (pk ServerBoundEncryptionResponse) Marshal() protocol.Packet {
	return protocol.MarshalPacket(
		ServerBoundEncryptionResponsePacketID,
		pk.SharedSecret,
		pk.VerifyToken,
	)
}

func UnmarshalServerBoundEncryptionResponse(packet protocol.Packet) (ServerBoundEncryptionResponse, ServerBoundEncryptionResponseNew, error) {
	var pk ServerBoundEncryptionResponse
	var pknew ServerBoundEncryptionResponseNew

	if packet.ID != ServerBoundEncryptionResponsePacketID {
		return pk, pknew, protocol.ErrInvalidPacketID
	}

	err := packet.Scan(
		&pk.SharedSecret,
		&pk.VerifyToken,
	)
	if err != nil {
		err = packet.Scan(
			&pknew.EncryptedSecretKey,
			&pknew.UseVerifyToken,
		)
		if err != nil {
			return pk, pknew, err
		}
		if pknew.UseVerifyToken {
			err = packet.Scan(
				&pknew.VerifyToken,
				&pknew.UseVerifyToken,
			)
			if err != nil {
				return pk, pknew, err
			}
			return pk, pknew, nil
		} else {
			err = packet.Scan(
				&pknew.Salt,
				&pknew.Signature,
			)
			if err != nil {
				return pk, pknew, err
			}
			return pk, pknew, nil
		}
	}

	return pk, pknew, nil
}
