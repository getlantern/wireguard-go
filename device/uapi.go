/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/wireguard-go/ipc"
)

type IPCError struct {
	code int64 // error code
	err  error // underlying/wrapped error
}

func (s IPCError) Error() string {
	return fmt.Sprintf("IPC error %d: %v", s.code, s.err)
}

func (s IPCError) Unwrap() error {
	return s.err
}

func (s IPCError) ErrorCode() int64 {
	return s.code
}

func ipcErrorf(code int64, msg string, args ...any) *IPCError {
	return &IPCError{code: code, err: fmt.Errorf(msg, args...)}
}

var byteBufferPool = &sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// IpcGetOperation implements the WireGuard configuration protocol "get" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcGetOperation(w io.Writer) error {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	buf := byteBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer byteBufferPool.Put(buf)
	sendf := func(format string, args ...any) {
		fmt.Fprintf(buf, format, args...)
		buf.WriteByte('\n')
	}
	keyf := func(prefix string, key *[32]byte) {
		buf.Grow(len(key)*2 + 2 + len(prefix))
		buf.WriteString(prefix)
		buf.WriteByte('=')
		const hex = "0123456789abcdef"
		for i := 0; i < len(key); i++ {
			buf.WriteByte(hex[key[i]>>4])
			buf.WriteByte(hex[key[i]&0xf])
		}
		buf.WriteByte('\n')
	}

	func() {
		// lock required resources

		device.net.RLock()
		defer device.net.RUnlock()

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		device.peers.RLock()
		defer device.peers.RUnlock()

		// serialize device related values

		if !device.staticIdentity.privateKey.IsZero() {
			keyf("private_key", (*[32]byte)(&device.staticIdentity.privateKey))
		}

		if device.net.port != 0 {
			sendf("listen_port=%d", device.net.port)
		}

		if device.net.fwmark != 0 {
			sendf("fwmark=%d", device.net.fwmark)
		}

		for _, peer := range device.peers.keyMap {
			// Serialize peer state.
			// Do the work in an anonymous function so that we can use defer.
			func() {
				peer.RLock()
				defer peer.RUnlock()

				keyf("public_key", (*[32]byte)(&peer.handshake.remoteStatic))
				keyf("preshared_key", (*[32]byte)(&peer.handshake.presharedKey))
				sendf("protocol_version=1")
				if peer.endpoint != nil {
					sendf("endpoint=%s", peer.endpoint.DstToString())
				}

				nano := peer.lastHandshakeNano.Load()
				secs := nano / time.Second.Nanoseconds()
				nano %= time.Second.Nanoseconds()

				sendf("last_handshake_time_sec=%d", secs)
				sendf("last_handshake_time_nsec=%d", nano)
				sendf("tx_bytes=%d", peer.txBytes.Load())
				sendf("rx_bytes=%d", peer.rxBytes.Load())
				sendf("persistent_keepalive_interval=%d", peer.persistentKeepaliveInterval.Load())

				// Amnezia obfuscation parameters
				if jc := peer.junkPacketCount.Load(); jc != 0 {
					sendf("jc=%d", jc)
				}
				if jmin := peer.junkPacketMinSize.Load(); jmin != 0 {
					sendf("jmin=%d", jmin)
				}
				if jmax := peer.junkPacketMaxSize.Load(); jmax != 0 {
					sendf("jmax=%d", jmax)
				}
				if s1 := peer.initPacketMagicHeader.Load(); s1 != 0 {
					sendf("s1=%d", s1)
				}
				if s2 := peer.responsePacketMagicHeader.Load(); s2 != 0 {
					sendf("s2=%d", s2)
				}
				if h1 := peer.underloadPacketMagicHeader.Load(); h1 != 0 {
					sendf("h1=%d", h1)
				}
				if h2 := peer.transportPacketMagicHeader.Load(); h2 != 0 {
					sendf("h2=%d", h2)
				}
				if h3 := peer.h3.Load(); h3 != 0 {
					sendf("h3=%d", h3)
				}
				if h4 := peer.h4.Load(); h4 != 0 {
					sendf("h4=%d", h4)
				}

				device.allowedips.EntriesForPeer(peer, func(prefix netip.Prefix) bool {
					sendf("allowed_ip=%s", prefix.String())
					return true
				})
			}()
		}
	}()

	// send lines (does not require resource locks)
	if _, err := w.Write(buf.Bytes()); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to write output: %w", err)
	}

	return nil
}

// IpcSetOperation implements the WireGuard configuration protocol "set" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcSetOperation(r io.Reader) (err error) {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	defer func() {
		if err != nil {
			device.log.Errorf("%v", err)
		}
	}()

	peer := new(ipcSetPeer)
	deviceConfig := true

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line means terminate operation.
			peer.handlePostConfig()
			return nil
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ipcErrorf(ipc.IpcErrorProtocol, "failed to parse line %q", line)
		}

		if key == "public_key" {
			if deviceConfig {
				deviceConfig = false
			}
			peer.handlePostConfig()
			// Load/create the peer we are now configuring.
			err := device.handlePublicKeyLine(peer, value)
			if err != nil {
				return err
			}
			continue
		}

		var err error
		if deviceConfig {
			err = device.handleDeviceLine(key, value)
		} else {
			err = device.handlePeerLine(peer, key, value)
		}
		if err != nil {
			return err
		}
	}
	peer.handlePostConfig()

	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return nil
}

func (device *Device) handleDeviceLine(key, value string) error {
	switch key {
	case "private_key":
		var sk NoisePrivateKey
		err := sk.FromMaybeZeroHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key: %w", err)
		}
		device.log.Verbosef("UAPI: Updating private key")
		device.SetPrivateKey(sk)

	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse listen_port: %w", err)
		}

		// update port and rebind
		device.log.Verbosef("UAPI: Updating listen port")

		device.net.Lock()
		device.net.port = uint16(port)
		device.net.Unlock()

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set listen_port: %w", err)
		}

	case "fwmark":
		mark, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid fwmark: %w", err)
		}

		device.log.Verbosef("UAPI: Updating fwmark")
		if err := device.BindSetMark(uint32(mark)); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to update fwmark: %w", err)
		}

	case "replace_peers":
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set replace_peers, invalid value: %v", value)
		}
		device.log.Verbosef("UAPI: Removing all peers")
		device.RemoveAllPeers()

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI device key: %v", key)
	}

	return nil
}

// An ipcSetPeer is the current state of an IPC set operation on a peer.
type ipcSetPeer struct {
	*Peer        // Peer is the current peer being operated on
	dummy   bool // dummy reports whether this peer is a temporary, placeholder peer
	created bool // new reports whether this is a newly created peer
	pkaOn   bool // pkaOn reports whether the peer had the persistent keepalive turn on
}

func (peer *ipcSetPeer) handlePostConfig() {
	if peer.Peer == nil || peer.dummy {
		return
	}
	if peer.created {
		peer.disableRoaming = peer.device.net.brokenRoaming && peer.endpoint != nil
	}
	if peer.device.isUp() {
		peer.Start()
		if peer.pkaOn {
			peer.SendKeepalive()
		}
		peer.SendStagedPackets()
	}
}

func (device *Device) handlePublicKeyLine(peer *ipcSetPeer, value string) error {
	// Load/create the peer we are configuring.
	var publicKey NoisePublicKey
	err := publicKey.FromHex(value)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to get peer by public key: %w", err)
	}

	// Ignore peer with the same public key as this device.
	device.staticIdentity.RLock()
	peer.dummy = device.staticIdentity.publicKey.Equals(publicKey)
	device.staticIdentity.RUnlock()

	if peer.dummy {
		peer.Peer = &Peer{}
	} else {
		peer.Peer = device.LookupPeer(publicKey)
	}

	peer.created = peer.Peer == nil
	if peer.created {
		peer.Peer, err = device.NewPeer(publicKey)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to create new peer: %w", err)
		}
		device.log.Verbosef("%v - UAPI: Created", peer.Peer)
	}
	return nil
}

func (device *Device) handlePeerLine(peer *ipcSetPeer, key, value string) error {
	switch key {
	case "update_only":
		// allow disabling of creation
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set update only, invalid value: %v", value)
		}
		if peer.created && !peer.dummy {
			device.RemovePeer(peer.handshake.remoteStatic)
			peer.Peer = &Peer{}
			peer.dummy = true
		}

	case "remove":
		// remove currently selected peer from device
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set remove, invalid value: %v", value)
		}
		if !peer.dummy {
			device.log.Verbosef("%v - UAPI: Removing", peer.Peer)
			device.RemovePeer(peer.handshake.remoteStatic)
		}
		peer.Peer = &Peer{}
		peer.dummy = true

	case "preshared_key":
		device.log.Verbosef("%v - UAPI: Updating preshared key", peer.Peer)

		peer.handshake.mutex.Lock()
		err := peer.handshake.presharedKey.FromHex(value)
		peer.handshake.mutex.Unlock()

		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set preshared key: %w", err)
		}

	case "endpoint":
		device.log.Verbosef("%v - UAPI: Updating endpoint", peer.Peer)
		endpoint, err := device.net.bind.ParseEndpoint(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set endpoint %v: %w", value, err)
		}
		peer.Lock()
		defer peer.Unlock()
		peer.endpoint = endpoint

	case "persistent_keepalive_interval":
		device.log.Verbosef("%v - UAPI: Updating persistent keepalive interval", peer.Peer)

		secs, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set persistent keepalive interval: %w", err)
		}

		old := peer.persistentKeepaliveInterval.Swap(uint32(secs))

		// Send immediate keepalive if we're turning it on and before it wasn't on.
		peer.pkaOn = old == 0 && secs != 0

	case "replace_allowed_ips":
		device.log.Verbosef("%v - UAPI: Removing all allowedips", peer.Peer)
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to replace allowedips, invalid value: %v", value)
		}
		if peer.dummy {
			return nil
		}
		device.allowedips.RemoveByPeer(peer.Peer)

	case "allowed_ip":
		device.log.Verbosef("%v - UAPI: Adding allowedip", peer.Peer)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set allowed ip: %w", err)
		}
		if peer.dummy {
			return nil
		}
		device.allowedips.Insert(prefix, peer.Peer)

	case "jc":
		device.log.Verbosef("%v - UAPI: Updating junk packet count", peer.Peer)
		jc, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set junk packet count: %w", err)
		}
		if jc > 1000 {
			return ipcErrorf(ipc.IpcErrorInvalid, "junk packet count too large: %d (max 1000)", jc)
		}
		peer.junkPacketCount.Store(uint32(jc))

	case "jmin":
		device.log.Verbosef("%v - UAPI: Updating junk packet minimum size", peer.Peer)
		jmin, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set junk packet minimum size: %w", err)
		}
		if jmin > 65535 {
			return ipcErrorf(ipc.IpcErrorInvalid, "junk packet minimum size too large: %d (max 65535)", jmin)
		}
		// Check that jmin <= jmax if both are set
		if jmax := peer.junkPacketMaxSize.Load(); jmax > 0 && uint32(jmin) > jmax {
			return ipcErrorf(ipc.IpcErrorInvalid, "junk packet minimum size (%d) must be <= maximum size (%d)", jmin, jmax)
		}
		peer.junkPacketMinSize.Store(uint32(jmin))

	case "jmax":
		device.log.Verbosef("%v - UAPI: Updating junk packet maximum size", peer.Peer)
		jmax, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set junk packet maximum size: %w", err)
		}
		if jmax > 65535 {
			return ipcErrorf(ipc.IpcErrorInvalid, "junk packet maximum size too large: %d (max 65535)", jmax)
		}
		// Check that jmax >= jmin if both are set
		if jmin := peer.junkPacketMinSize.Load(); jmin > 0 && uint32(jmax) < jmin {
			return ipcErrorf(ipc.IpcErrorInvalid, "junk packet maximum size (%d) must be >= minimum size (%d)", jmax, jmin)
		}
		peer.junkPacketMaxSize.Store(uint32(jmax))

	case "s1":
		device.log.Verbosef("%v - UAPI: Updating init packet magic header", peer.Peer)
		s1, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set init packet magic header: %w", err)
		}
		peer.initPacketMagicHeader.Store(uint32(s1))

	case "s2":
		device.log.Verbosef("%v - UAPI: Updating response packet magic header", peer.Peer)
		s2, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set response packet magic header: %w", err)
		}
		peer.responsePacketMagicHeader.Store(uint32(s2))

	case "h1":
		device.log.Verbosef("%v - UAPI: Updating underload packet magic header", peer.Peer)
		h1, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set underload packet magic header: %w", err)
		}
		peer.underloadPacketMagicHeader.Store(uint32(h1))

	case "h2":
		device.log.Verbosef("%v - UAPI: Updating transport packet magic header", peer.Peer)
		h2, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set transport packet magic header: %w", err)
		}
		peer.transportPacketMagicHeader.Store(uint32(h2))

	case "h3":
		device.log.Verbosef("%v - UAPI: Updating h3 obfuscation parameter", peer.Peer)
		h3, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set h3 obfuscation parameter: %w", err)
		}
		peer.h3.Store(uint32(h3))

	case "h4":
		device.log.Verbosef("%v - UAPI: Updating h4 obfuscation parameter", peer.Peer)
		h4, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set h4 obfuscation parameter: %w", err)
		}
		peer.h4.Store(uint32(h4))

	case "protocol_version":
		if value != "1" {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid protocol version: %v", value)
		}

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI peer key: %v", key)
	}

	return nil
}

func (device *Device) IpcGet() (string, error) {
	buf := new(strings.Builder)
	if err := device.IpcGetOperation(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (device *Device) IpcSet(uapiConf string) error {
	return device.IpcSetOperation(strings.NewReader(uapiConf))
}

func (device *Device) IpcHandle(socket net.Conn) {
	defer socket.Close()

	buffered := func(s io.ReadWriter) *bufio.ReadWriter {
		reader := bufio.NewReader(s)
		writer := bufio.NewWriter(s)
		return bufio.NewReadWriter(reader, writer)
	}(socket)

	for {
		op, err := buffered.ReadString('\n')
		if err != nil {
			return
		}

		// handle operation
		switch op {
		case "set=1\n":
			err = device.IpcSetOperation(buffered.Reader)
		case "get=1\n":
			var nextByte byte
			nextByte, err = buffered.ReadByte()
			if err != nil {
				return
			}
			if nextByte != '\n' {
				err = ipcErrorf(ipc.IpcErrorInvalid, "trailing character in UAPI get: %q", nextByte)
				break
			}
			err = device.IpcGetOperation(buffered.Writer)
		default:
			device.log.Errorf("invalid UAPI operation: %v", op)
			return
		}

		// write status
		var status *IPCError
		if err != nil && !errors.As(err, &status) {
			// shouldn't happen
			status = ipcErrorf(ipc.IpcErrorUnknown, "other UAPI error: %w", err)
		}
		if status != nil {
			device.log.Errorf("%v", status)
			fmt.Fprintf(buffered, "errno=%d\n\n", status.ErrorCode())
		} else {
			fmt.Fprintf(buffered, "errno=0\n\n")
		}
		buffered.Flush()
	}
}
