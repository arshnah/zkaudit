package zkaudit

import (
	"encoding/json"
	"os"
)

type HAR struct {
	Log struct {
		Entries []Entry `json:"entries"`
	} `json:"log"`
}

type Entry struct {
	StartedDateTime string   `json:"startedDateTime"`
	Request         Request  `json:"request"`
	Response        Response `json:"response"`
}

type Request struct {
	Method   string   `json:"method"`
	URL      string   `json:"url"`
	Headers  []Header `json:"headers"`
	Cookies  []Cookie `json:"cookies"`
	PostData *struct {
		MimeType string `json:"mimeType"`
		Text     string `json:"text"`
	} `json:"postData"`
}

type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Response struct {
	Status  int      `json:"status"`
	Headers []Header `json:"headers"`
	Cookies []Cookie `json:"cookies"`
	Content struct {
		MimeType string `json:"mimeType"`
		Text     string `json:"text"`
		Encoding string `json:"encoding"`
	} `json:"content"`
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func LoadHAR(path string) (*HAR, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var h HAR
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func SaveHAR(h *HAR, path string) error {
	data, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
