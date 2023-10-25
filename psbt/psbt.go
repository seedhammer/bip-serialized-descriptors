package psbt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// This file implements BIP-174 decoding and encoding and
// includes a very basic PSBT decoder for verification.

type ExtendedKey struct {
	MasterFingerprint uint32
	Path              []uint32
	Key               []byte
}

func DecodePSBTXpub(e Entry) (ExtendedKey, error) {
	val := e.Val
	if len(val) < 4 || len(val)%4 != 0 {
		return ExtendedKey{}, io.ErrUnexpectedEOF
	}
	k := ExtendedKey{
		Key: e.Key[1:],
	}
	k.MasterFingerprint = binary.BigEndian.Uint32(val)
	val = val[4:]
	for len(val) > 0 {
		p := binary.LittleEndian.Uint32(val)
		val = val[4:]
		k.Path = append(k.Path, p)
	}
	return k, nil
}

func Decode(data []byte) error {
	const PSBT_GLOBAL_UNSIGNED_TX = 0x00

	// Verify magic.
	const psbtMagic = "psbt\xff"
	if !bytes.HasPrefix(data, []byte(psbtMagic)) {
		return errors.New("psbt: invalid magic")
	}
	data = data[len(psbtMagic):]

	// Read global map.
	m, n, err := DecodeMap(data)
	data = data[n:]
	if err != nil {
		return fmt.Errorf("psbt: %w", err)
	}
	for _, e := range m {
		switch k := e.Key[0]; k {
		case PSBT_GLOBAL_UNSIGNED_TX:
			fmt.Printf("PSBT_GLOBAL_UNSIGNED_TX: %#x\n", e.Val)
		default:
			fmt.Printf("Unknown global entry: key %#x, value %#x\n", k, e.Val)
		}
	}

	// Read input and output maps.
	for {
		m, n, err := DecodeMap(data)
		data = data[n:]
		if err != nil {
			return fmt.Errorf("psbt: %w", err)
		}
		if n == 0 {
			// No more maps.
			break
		}
		fmt.Println("\nInput/output map:")
		for _, e := range m {
			switch k := e.Key[0]; k {
			default:
				fmt.Printf("Unknown input/output entry: key %#x, value %#x\n", k, e.Val)
			}
		}
	}
	return nil
}

type Entry struct {
	Key, Val []byte
}

func (e Entry) Write(w *bytes.Buffer) {
	writeVarInt(w, uint64(len(e.Key)))
	w.Write(e.Key)
	writeVarInt(w, uint64(len(e.Val)))
	w.Write(e.Val)
}

func writeVarInt(w *bytes.Buffer, v uint64) {
	bo := binary.LittleEndian
	switch {
	case v < 0xfd:
		w.WriteByte(uint8(v))
	case v <= 0xffff:
		var buf [2]uint8
		bo.PutUint16(buf[:], uint16(v))
		w.Write(buf[:])
	case v <= 0xffff_ffff:
		var buf [4]uint8
		bo.PutUint32(buf[:], uint32(v))
		w.Write(buf[:])
	default:
		var buf [8]uint8
		bo.PutUint64(buf[:], uint64(v))
		w.Write(buf[:])
	}
}

func DecodeMap(data []byte) ([]Entry, int, error) {
	var m []Entry
	n := 0
	for {
		key, val, n1, err := decodeKeyVal(data)
		data = data[n1:]
		n += n1
		if err != nil {
			if errors.Is(err, io.EOF) {
				return m, n, nil
			}
			return nil, n, err
		}
		m = append(m, Entry{key, val})
	}
}

func decodeKeyVal(data []byte) ([]byte, []byte, int, error) {
	keyLen, n1 := decodeVarInt(data)
	data = data[n1:]
	if n1 == 0 || keyLen > uint64(len(data)) {
		return nil, nil, 0, io.EOF
	}
	if keyLen == 0 {
		// End of map.
		return nil, nil, n1, io.EOF
	}
	key := data[:keyLen]
	data = data[keyLen:]
	valLen, n2 := decodeVarInt(data)
	data = data[n2:]
	if n2 == 0 || valLen > uint64(len(data)) {
		return nil, nil, 0, io.ErrUnexpectedEOF
	}
	val := data[:valLen]
	data = data[valLen:]
	return key, val, n1 + n2 + int(keyLen+valLen), nil
}

// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer.
func decodeVarInt(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	bo := binary.LittleEndian
	switch v := data[0]; v {
	case 0xfd:
		// 16 bit value.
		if len(data) < 3 {
			return 0, 0
		}
		v := bo.Uint16(data[1:])
		return uint64(v), 3
	case 0xfe:
		// 32 bit value.
		if len(data) < 5 {
			return 0, 0
		}
		v := bo.Uint32(data[1:])
		return uint64(v), 5
	case 0xff:
		// 64 bit value.
		if len(data) < 9 {
			return 0, 0
		}
		v := bo.Uint64(data[1:])
		return v, 9
	default:
		// 8 bit value.
		return uint64(v), 1
	}
}
