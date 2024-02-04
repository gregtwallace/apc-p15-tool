package app

import (
	"encoding/binary"
	"errors"

	"github.com/sigurn/crc16"
)

// makeFileHeader generates the 228 byte header to prepend to the .p15
// as required by APC UPS NMC. Contrary to the apc_tools repo, it does
// mot appear the header changes based on key size.
func makeFileHeader(p15File []byte) ([]byte, error) {
	// original reference code from: https://github.com/bbczeuz/apc_tools
	// // add APC header
	// *(uint32_t *)(buf + 0) = 1; // always 1
	// *(uint32_t *)(buf + 4) = 1; // always 1
	// strncpy((char *)(buf + 8), "SecurityWizard103", 0xC8); // apparently supposed to identify the creating tool, SecWiz v1.04 sill puts 103 here
	// *(uint32_t *)(buf + 208) = 1; // always 1
	// *(uint32_t *)(buf + 212) = 1; // always 1
	// *(uint32_t *)(buf + 216) = fileSize; // size of the following data
	// *(uint32_t *)(buf + 208) = keySize; // 1 for 1024 key, otherwise (2048 bit) 2
	// // 16 bit checksums are moved to 32 bit int with sign-extension
	// *(uint32_t *)(buf + 220) = (int32_t)calc_cksum(0, buf + 228, fileSize); // checksum of the original file
	// *(uint32_t *)(buf + 224) = (int32_t)calc_cksum(0, buf, 224); // checksum of the APC header

	// NOTE: This line is unused as it seems the APC CLI tool v1.0.0 code always writes this as a 1 (regardless of key length)
	// 		*(uint32_t *)(buf + 208) = keySize; // 1 for 1024 key, otherwise (2048 bit) 2
	// Unsure why this was in original code but seems irrelevant

	header := make([]byte, 228)

	// always 1
	header[0] = 1

	// always 1
	header[4] = 1

	// apparently supposed to identify the creating tool
	toolName := "NMCSecurityWizardCLI100"
	toolNameBytes := []byte(toolName)
	if len(toolNameBytes) > 200 {
		return nil, errors.New("tool name is too big to fit in header")
	}
	copy(header[8:], toolNameBytes)

	// always 1
	header[208] = 1

	// always 1
	header[212] = 1

	// size of the data after the header (the actual p15 file)
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(p15File)))
	copy(header[216:], size)

	// check sums (CRC Table)
	checksumTable := crc16.MakeTable(crc16.CRC16_XMODEM)

	// NOTE: 16 bit checksums are moved to 32 bit int with sign-extension by converting
	// to int16 and then to uint32

	// file checksum
	fileChecksum := make([]byte, 4)
	binary.LittleEndian.PutUint32(fileChecksum, uint32(int16(crc16.Checksum(p15File, checksumTable))))
	copy(header[220:], fileChecksum)

	// header checksum
	headerChecksum := make([]byte, 4)
	binary.LittleEndian.PutUint32(headerChecksum, uint32(int16(crc16.Checksum(header[:224], checksumTable))))
	copy(header[224:], headerChecksum)

	return header, nil
}
