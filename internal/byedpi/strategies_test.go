package byedpi

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseStrategiesQuotedArgsAndEscapes(t *testing.T) {
	input := `fake | --fake-data ":hello world" --fake-sni '*.example.test' --oob-data "A B"
fake duplicate | --fake-data ":hello world" --fake-sni '*.example.test' --oob-data "A B"
path | --hosts "C:\Users\Test Data\hosts.txt" --fake-data ':foo bar'
escaped | --fake-data :foo\ bar
`
	list, err := ParseStrategies(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("want 3 deduplicated strategies, got %+v", list)
	}
	for i, want := range [][]string{
		{"--fake-data", ":hello world", "--fake-sni", "*.example.test", "--oob-data", "A B"},
		{"--hosts", `C:\Users\Test Data\hosts.txt`, "--fake-data", ":foo bar"},
		{"--fake-data", ":foo bar"},
	} {
		if !reflect.DeepEqual(list[i].Args, want) {
			t.Errorf("strategy %d: got %q, want %q", i, list[i].Args, want)
		}
	}
}

func TestParseStrategiesRejectsReservedListenerAndRelayOptions(t *testing.T) {
	for _, options := range []string{
		"-i0.0.0.0 --split 1", "-p1080 --split 1", "-Ui0.0.0.0",
		"-Xp1080", "-C127.0.0.1:9000", "-I0.0.0.0",
		"--ip=0.0.0.0", "--port=4444", "--daemon", "--pidfile=/tmp/x",
		"--connect-to=127.0.0.1:9000", "--transparent",
		"--protect-path=/tmp/x", "--conn-ip=0.0.0.0",
		"--con=127.0.0.1:9000", "--por=4444", "--ip", "--",
		"--unknowable 1",
	} {
		t.Run(options, func(t *testing.T) {
			if _, err := ParseStrategies(strings.NewReader("unsafe | " + options)); err == nil {
				t.Fatalf("unsafe option accepted: %q", options)
			}
		})
	}
	for _, line := range []string{
		`bad | --fake-data "unclosed`,
		`bad | --fake-data ""`,
	} {
		if _, err := ParseStrategies(strings.NewReader(line)); err == nil {
			t.Errorf("malformed strategy accepted: %q", line)
		}
	}
}

func TestParseStrategiesPreservesExistingCatalogue(t *testing.T) {
	items, err := ParseStrategies(strings.NewReader(DefaultStrategies))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 9 {
		t.Fatalf("built-in ByeDPI strategies changed unexpectedly: %d", len(items))
	}
}
