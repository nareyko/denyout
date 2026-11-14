package desktop

import "testing"

func TestLooksLikeSecretInCmd(t *testing.T) {
	if !looksLikeSecretInCmd("curl -H 'Authorization: Bearer sk-abc'") {
		t.Fatal("expected secret-ish")
	}
	if looksLikeSecretInCmd("python app.py --port 8080") {
		t.Fatal("clean command")
	}
}

func TestAppendRemovePID(t *testing.T) {
	var list []int
	list = appendPID(list, 0)
	if len(list) != 0 {
		t.Fatal(list)
	}
	list = appendPID(list, 42)
	list = appendPID(list, 42)
	if len(list) != 1 {
		t.Fatal(list)
	}
	list = appendPID(list, 7)
	list = removePID(list, 42)
	if len(list) != 1 || list[0] != 7 {
		t.Fatal(list)
	}
}
