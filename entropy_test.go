package zkaudit

import "testing"

func TestHighEntropyDetectsRawBinaryCiphertext(t *testing.T) {
	rawBinary := "\x83\xf9\x1eW\x80\x1b\xb2\t\xa9PB\xc1D\x10\xbb\x15\xa9'\x05\xa3\x9a\xae\xf9\x8a\x17J\xdep\xffx123\xbe\xdee\xd4\xb8\xebO"
	h := harWithPostData(rawBinary)

	report := Scan(h, []Secret{{Label: "irrelevant", Value: "not-present-anywhere"}})
	if !report.CiphertextLikely {
		t.Fatal("expected raw high-entropy binary (the actual shape of CipherDrop's real traffic) to be flagged ciphertext-likely, base64-density alone misses this because raw octets aren't restricted to the base64 charset")
	}
}

func TestLowEntropyPlainTextNotFlaggedAsCiphertext(t *testing.T) {
	h := harWithPostData(`{"message":"just a normal english sentence with words in it"}`)

	report := Scan(h, []Secret{{Label: "irrelevant", Value: "not-present-anywhere"}})
	if report.CiphertextLikely {
		t.Fatal("expected ordinary low-entropy plaintext JSON to not be flagged as ciphertext-likely")
	}
}
