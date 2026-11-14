// Builds crates/client/tests/fixtures/dgw.json: DGW frames as mautrix-meta's own `dgw`
// package encodes them, so the Rust codec is checked against the implementation that talks
// to Meta's gateway today, not against a reading of it.
//
//   docker run --rm -v "$PWD/scripts/dgw-fixture:/src" -v <mautrix-meta checkout>:/meta:ro \
//     -v "$PWD/out:/out" -w /src golang:1.27-alpine sh -c "go mod tidy && go run ."
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"go.mau.fi/mautrix-meta/pkg/messagix/dgw"
)

type Case struct {
	Name  string         `json:"name"`
	Hex   string         `json:"hex"`
	Frame map[string]any `json:"frame"`
}

func ptr(b byte) *byte { return &b }

func main() {
	frames := []struct {
		name  string
		frame dgw.Frame
		desc  map[string]any
	}{
		{"ping", &dgw.PingFrame{}, map[string]any{"type": "ping"}},
		{"pong", &dgw.PongFrame{}, map[string]any{"type": "pong"}},
		{"deauth", &dgw.DeauthFrame{}, map[string]any{"type": "deauth"}},
		{"drain", &dgw.DrainFrame{DrainReason: dgw.DrainReasonMaxConnectionAgeExceeded}, map[string]any{"type": "drain", "reason": 5}},
		{"ack", &dgw.AckFrame{StreamID: 3, AckID: 7}, map[string]any{"type": "ack", "stream": 3, "ack": 7}},
		{"data", &dgw.DataFrame{StreamID: 2, AckID: 5, RequiresAck: true, Payload: []byte(`{"request_id":1,"type":3}`)},
			map[string]any{"type": "data", "stream": 2, "ack": 5, "requires_ack": true, "payload": `{"request_id":1,"type":3}`}},
		{"data, no ack", &dgw.DataFrame{StreamID: 65535, AckID: 32767, Payload: []byte("x")},
			map[string]any{"type": "data", "stream": 65535, "ack": 32767, "requires_ack": false, "payload": "x"}},
		{"extended data", &dgw.DataFrame{StreamID: 9, AckID: 1, RequiresAck: true, ContentType: ptr(0), Payload: []byte(`{"a":1}`)},
			map[string]any{"type": "data", "stream": 9, "ack": 1, "requires_ack": true, "content_type": 0, "payload": `{"a":1}`}},
		// Longer than 64 KiB, so the length's third byte is used.
		{"large data", &dgw.DataFrame{StreamID: 6, AckID: 2, RequiresAck: true, Payload: bytes.Repeat([]byte("a"), 70000)},
			map[string]any{"type": "data", "stream": 6, "ack": 2, "requires_ack": true, "payload": strings.Repeat("a", 70000)}},
		{"end of data", &dgw.EndOfDataFrame{StreamID: 4}, map[string]any{"type": "end_of_data", "stream": 4}},
		{"end of data with reason", &dgw.EndOfDataWithReasonFrame{StreamID: 4, Reason: dgw.EndOfDataReasonDraining},
			map[string]any{"type": "end_of_data", "stream": 4, "reason": 8}},
		{"establish stream", &dgw.EstablishStreamFrame{StreamID: 1, RawParameters: json.RawMessage(`{"x-dgw-app-XRSS-method":"Falco","x-dgw-app-stream-group":"group1"}`)},
			map[string]any{"type": "establish", "stream": 1, "parameters": `{"x-dgw-app-XRSS-method":"Falco","x-dgw-app-stream-group":"group1"}`}},
	}
	out := struct {
		Frames []Case `json:"frames"`
		// Several frames in one websocket message, as the gateway batches them.
		Batch      string   `json:"batch"`
		BatchTypes []string `json:"batchTypes"`
	}{}
	var batch []byte
	for _, f := range frames {
		out.Frames = append(out.Frames, Case{f.name, hex.EncodeToString(f.frame.MarshalAppend(nil)), f.desc})
		batch = f.frame.MarshalAppend(batch)
	}
	// Read the batch back with mautrix's own parser, so the fixture records what it sees.
	rest := batch
	for len(rest) > 0 {
		frame := dgw.CheckFrameType(rest)
		var err error
		rest, err = frame.Unmarshal(rest)
		if err != nil {
			panic(err)
		}
		out.BatchTypes = append(out.BatchTypes, frameName(frame))
	}
	out.Batch = hex.EncodeToString(batch)
	data, _ := json.MarshalIndent(out, "", " ")
	if err := os.WriteFile("/out/dgw.json", data, 0o644); err != nil {
		panic(err)
	}
}

func frameName(f dgw.Frame) string {
	switch f.(type) {
	case *dgw.PingFrame:
		return "ping"
	case *dgw.PongFrame:
		return "pong"
	case *dgw.DeauthFrame:
		return "deauth"
	case *dgw.DrainFrame:
		return "drain"
	case *dgw.AckFrame:
		return "ack"
	case *dgw.DataFrame:
		return "data"
	case *dgw.EndOfDataFrame, *dgw.EndOfDataWithReasonFrame:
		return "end_of_data"
	case *dgw.EstablishStreamFrame:
		return "establish"
	default:
		return "unsupported"
	}
}
