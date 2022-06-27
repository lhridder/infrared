package protocol

import (
	"errors"
)

var (
	ErrInvalidPacketID     = errors.New("invalid packet id")
	ErrInvalidPacketLength = errors.New("packet length incorrect")
)
