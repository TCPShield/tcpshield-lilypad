package main

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

const PublicKey = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEEvy/Eh9v5QMkdzeTw1tPMCEljzKgw0zWwt926zRZJT9sv/OLEwkE/rB1JrH3XXMTsv8w7gPzV4k9BjUAcZ1xH1yNG/AhNA23DQiFSXye/WFB+KlSr4hkx68niNJdvoPs"

func Verify(serverAddress string, realIP *string) error {
	parts := strings.Split(serverAddress, "///")
	if len(parts) != 4 {
		return errors.New("invalid payload length")
	}

	// TODO: Implement CIDR Validator for whitelist
	// TODO: Implement support for Geyser

	var hostname string
	var playerIP string
	var playerPort uint16
	var timestamp uint64
	var signature string

	if err := processParts(parts, &hostname, &playerIP, &playerPort, &timestamp, &signature); err != nil {
		return err
	}

	if !validateTimestamp(timestamp) {
		return errors.New("invalid timestamp, check system time")
	}

	if err := verifySignature(hostname, playerIP, playerPort, timestamp, signature); err != nil {
		return err
	}

	*realIP = playerIP

	return nil
}

func processParts(parts []string, hostname *string, playerIP *string, playerPort *uint16, timestamp *uint64, signature *string) error {
	// hostname
	*hostname = parts[0]

	// player ip:port
	ipData := strings.Split(parts[1], ":")
	*playerIP = ipData[0]
	port, err := strconv.ParseUint(ipData[1], 10, 16)
	if err != nil {
		return errors.New("invalid port")
	}
	*playerPort = uint16(port)

	// timestamp
	ts, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return errors.New("invalid timestamp")
	}
	*timestamp = ts

	// signature
	*signature = parts[3]

	return nil
}

func verifySignature(hostname string, playerIP string, playerPort uint16, timestamp uint64, signature string) error {
	// reconstruct payload to verify
	payload := hostname + "///" + playerIP + ":" + strconv.FormatUint(uint64(playerPort), 10) + "///" + strconv.FormatUint(timestamp, 10)

	sig := struct{ R, S *big.Int }{}
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return errors.New("invalid tcpshield public key")
	}

	if _, err := asn1.Unmarshal(sigBytes, &sig); err != nil {
		return errors.New(fmt.Sprint("failed to unmarshal signature", err))
	}

	hash := sha512.New()
	hash.Write([]byte(payload))

	bytes, _ := base64.StdEncoding.DecodeString(PublicKey)
	pk, _ := x509.ParsePKIXPublicKey(bytes)
	publicKey := pk.(*ecdsa.PublicKey)

	if !ecdsa.Verify(publicKey, hash.Sum(nil), sig.R, sig.S) {
		return errors.New("failed to verify payload signature")
	}

	return nil
}

// TODO: Make time range configurable, 3s will do for now
func validateTimestamp(timestamp uint64) bool {
	return (uint64(time.Now().Unix()))-timestamp < 3
}
