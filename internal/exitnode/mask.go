// Package exitnode is PattNG's Aether exit-node, for platforms without Xray.
//
// PattNG never lets the Aether core dial the internet itself: the core runs
// with --upstream socks5://127.0.0.1:<port>, a loopback inbound of Xray whose
// "exit-node" outbound is a plain freedom outbound carrying the profile's
// finalMask. Every connection the core makes (WARP API registration, ECH key
// lookup, the gateway scan and the MASQUE/WireGuard tunnel itself) therefore
// leaves through that mask: TCP through TLS-hello fragmentation, UDP behind
// bursts of random noise datagrams. This package is that exit-node: a SOCKS5
// server with CONNECT and UDP ASSOCIATE whose outgoing sockets carry the
// same masks, ported from patterniha/xray-core v26.10.19
// (transport/internet/finalmask/{fragment,noise}, MPL-2.0), and configured
// with the same finalMask JSON PattNG ships as presets.
package exitnode

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Range is Xray's Int32Range: a number, or a string "n" or "min-max".
type Range struct{ Min, Max int64 }

func (r *Range) UnmarshalJSON(b []byte) error {
	var text string
	if err := json.Unmarshal(b, &text); err != nil {
		var n int64
		if err := json.Unmarshal(b, &n); err != nil {
			return fmt.Errorf("range: want a number or \"min-max\", got %s", b)
		}
		r.Min, r.Max = n, n
		return nil
	}
	low, high, found := strings.Cut(strings.TrimSpace(text), "-")
	min, err := strconv.ParseInt(strings.TrimSpace(low), 10, 32)
	if err != nil {
		return fmt.Errorf("range %q: %w", text, err)
	}
	max := min
	if found {
		if max, err = strconv.ParseInt(strings.TrimSpace(high), 10, 32); err != nil {
			return fmt.Errorf("range %q: %w", text, err)
		}
	}
	if min > max {
		min, max = max, min
	}
	r.Min, r.Max = min, max
	return nil
}

// randBetween is Xray's crypto.RandBetween: uniform in [from, to).
func randBetween(from, to int64) int64 {
	if from == to {
		return from
	}
	if to < from {
		from, to = to, from
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	return from + int64(binary.BigEndian.Uint64(b[:])%uint64(to-from))
}

// Fragment is one "fragment" TCP mask.
type Fragment struct {
	PacketsFrom, PacketsTo int64 // tlshello is 0..1
	Lengths, Delays        []Range
	MaxSplit               Range
}

// Noise is one "noise" UDP mask.
type Noise struct {
	Reset Range
	Items []NoiseItem
}

// NoiseItem is either fixed bytes or Rand random bytes in RandRange.
type NoiseItem struct {
	Rand, RandRange, Delay Range
	Packet                 []byte
}

// Mask is a parsed finalMask: TCP masks wrap in order, the first one
// innermost, exactly as Xray's FinalMask.DialTCP stacks them.
type Mask struct {
	TCP []Fragment
	UDP []Noise
}

type rawMask struct {
	TCP []struct {
		Type     string `json:"type"`
		Settings struct {
			Packets  string  `json:"packets"`
			Length   *Range  `json:"length"`
			Delay    *Range  `json:"delay"`
			Lengths  []Range `json:"lengths"`
			Delays   []Range `json:"delays"`
			MaxSplit Range   `json:"maxSplit"`
		} `json:"settings"`
	} `json:"tcp"`
	UDP []struct {
		Type     string `json:"type"`
		Settings struct {
			Reset Range `json:"reset"`
			Noise []struct {
				Rand      Range  `json:"rand"`
				RandRange *Range `json:"randRange"`
				Type      string `json:"type"`
				Packet    string `json:"packet"`
				Delay     Range  `json:"delay"`
			} `json:"noise"`
		} `json:"settings"`
	} `json:"udp"`
}

// ParseMask reads the subset of Xray's finalMask that PattNG's exit-node
// presets use: tcp "fragment" and udp "noise" (rand or str packets).
func ParseMask(text string) (Mask, error) {
	var raw rawMask
	dec := json.NewDecoder(strings.NewReader(text))
	if err := dec.Decode(&raw); err != nil {
		return Mask{}, fmt.Errorf("finalMask: %w", err)
	}
	var m Mask
	for _, t := range raw.TCP {
		if !strings.EqualFold(t.Type, "fragment") {
			return Mask{}, fmt.Errorf("finalMask: unsupported tcp mask %q", t.Type)
		}
		s := t.Settings
		var f Fragment
		switch packets := strings.ToLower(strings.TrimSpace(s.Packets)); packets {
		case "tlshello":
			f.PacketsFrom, f.PacketsTo = 0, 1
		case "":
		default:
			var r Range
			if err := r.UnmarshalJSON([]byte(strconv.Quote(packets))); err != nil {
				return Mask{}, err
			}
			if r.Min == 0 {
				return Mask{}, errors.New("finalMask: fragment packets can't start at 0")
			}
			f.PacketsFrom, f.PacketsTo = r.Min, r.Max
		}
		f.Lengths, f.Delays = s.Lengths, s.Delays
		if len(f.Lengths) == 0 {
			if s.Length == nil {
				return Mask{}, errors.New("finalMask: fragment needs lengths")
			}
			f.Lengths = []Range{*s.Length}
		}
		if f.Lengths[len(f.Lengths)-1].Min == 0 {
			return Mask{}, errors.New("finalMask: last lengths entry min can't be 0")
		}
		if len(f.Delays) == 0 {
			if s.Delay != nil {
				f.Delays = []Range{*s.Delay}
			} else {
				f.Delays = []Range{{}}
			}
		}
		f.MaxSplit = s.MaxSplit
		m.TCP = append(m.TCP, f)
	}
	for _, u := range raw.UDP {
		if !strings.EqualFold(u.Type, "noise") {
			return Mask{}, fmt.Errorf("finalMask: unsupported udp mask %q", u.Type)
		}
		n := Noise{Reset: u.Settings.Reset}
		for _, item := range u.Settings.Noise {
			it := NoiseItem{Rand: item.Rand, Delay: item.Delay, RandRange: Range{0, 255}}
			if item.RandRange != nil {
				if item.RandRange.Min < 0 || item.RandRange.Max > 255 {
					return Mask{}, errors.New("finalMask: invalid randRange")
				}
				it.RandRange = *item.RandRange
			}
			if item.Packet != "" {
				if item.Rand.Max > 0 {
					return Mask{}, errors.New("finalMask: noise item has both packet and rand")
				}
				if t := strings.ToLower(item.Type); t != "" && t != "str" {
					return Mask{}, fmt.Errorf("finalMask: unsupported noise packet type %q", item.Type)
				}
				it.Packet = []byte(item.Packet)
			}
			n.Items = append(n.Items, it)
		}
		m.UDP = append(m.UDP, n)
	}
	return m, nil
}

// PattNG's finalMask presets (V2rayNG/app/src/main/res/values/arrays.xml at
// PattNG 89c760c), kept as the same JSON so a preset here is the preset there.
const (
	PresetTLSHelloZero = "tlshello-0-len"
	PresetTLSHello     = "tlshello"
	PresetUDPNoise     = "udp-noise"
)

var presetJSON = map[string]string{
	PresetTLSHelloZero: `{"tcp": [
  {"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"}},
  {"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}
]}`,
	PresetTLSHello: `{"tcp": [
  {"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["6", "98", "1"], "delays": ["0"], "maxSplit": "0"}},
  {"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}
]}`,
	PresetUDPNoise: `{"udp": [{"type": "noise", "settings": {"reset": "28", "noise": [` +
		strings.TrimSuffix(strings.Repeat(`{"rand": "1200-1230", "delay": "10"},`, 24), ",") + `]}}]}`,
}

// Preset returns a named PattNG preset.
func Preset(name string) (Mask, error) {
	text, ok := presetJSON[name]
	if !ok {
		return Mask{}, fmt.Errorf("unknown exit-node preset %q", name)
	}
	return ParseMask(text)
}

// Presets lists the preset names in PattNG's menu order.
func Presets() []string { return []string{PresetTLSHelloZero, PresetTLSHello, PresetUDPNoise} }
