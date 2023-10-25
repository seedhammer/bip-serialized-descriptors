package cod

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/seedhammer/bip-serialized-descriptors/psbt"
)

// This file implements https://github.com/BlockchainCommons/Research/issues/135
// with no other external dependency than the BIP-174 encoding and decoding
// implemented in psbt.go.

const HardenedKeyStart = 0x80000000 // 2^31

const SerializeDescMagic = "desc\xff"

const (
	// The field type for the output descriptor.
	GLOBAL_OUTPUT_DESCRIPTOR = 0x00
	// Field type for name.
	GLOBAL_NAME = 0x01

	// Field type for extended key, encoded as PSBT_GLOBAL_XPUB.
	KEY_XPUB = 0x00
)

type OutputDescriptor struct {
	Name       string
	Descriptor string
	Keys       []psbt.ExtendedKey
}

func Encode(desc OutputDescriptor) ([]byte, error) {
	// Encode magic.
	buf := new(bytes.Buffer)
	buf.Write([]byte(SerializeDescMagic))

	// Encode global map describing the output descriptor.
	psbt.Entry{
		Key: []byte{GLOBAL_NAME},
		Val: []byte(desc.Name),
	}.Write(buf)
	psbt.Entry{
		Key: []byte{GLOBAL_OUTPUT_DESCRIPTOR},
		Val: []byte(desc.Descriptor),
	}.Write(buf)
	buf.WriteByte(0x00)

	// Write a map for each key.
	for _, k := range desc.Keys {
		var mfpAndPath []byte
		mfpAndPath = binary.BigEndian.AppendUint32(mfpAndPath, k.MasterFingerprint)
		for _, p := range k.Path {
			mfpAndPath = binary.LittleEndian.AppendUint32(mfpAndPath, p)
		}
		psbt.Entry{
			Key: append([]byte{KEY_XPUB}, k.Key...),
			Val: mfpAndPath,
		}.Write(buf)
		buf.WriteByte(0x00)
	}

	return buf.Bytes(), nil
}

func Decode(data []byte) (OutputDescriptor, error) {
	const psbtMagic = "psbt\xff"
	if !bytes.HasPrefix(data, []byte(SerializeDescMagic)) {
		return OutputDescriptor{}, errors.New("serdesc: invalid magic")
	}
	data = data[len(psbtMagic):]

	// Read global map.
	m, n, err := psbt.DecodeMap(data)
	data = data[n:]
	if err != nil {
		return OutputDescriptor{}, fmt.Errorf("serdesc: %w", err)
	}
	var desc OutputDescriptor
	for _, e := range m {
		switch k := e.Key[0]; k {
		case GLOBAL_NAME:
			desc.Name = string(e.Val)
		case GLOBAL_OUTPUT_DESCRIPTOR:
			desc.Descriptor = string(e.Val)
		}
	}

	// Read keys.
	for {
		m, n, err := psbt.DecodeMap(data)
		data = data[n:]
		if err != nil {
			return OutputDescriptor{}, fmt.Errorf("serdesc: %w", err)
		}
		if n == 0 {
			// No more keys.
			break
		}
		for i, e := range m {
			var key psbt.ExtendedKey
			switch k := e.Key[0]; k {
			case KEY_XPUB:
				k, err := psbt.DecodePSBTXpub(e)
				if err != nil {
					return OutputDescriptor{}, fmt.Errorf("serdesc: invalid key at index %d: %w", i, err)
				}
				key = k
			}
			desc.Keys = append(desc.Keys, key)
		}
	}
	return desc, nil
}
