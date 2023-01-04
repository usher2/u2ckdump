package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

// DumpAnswer - "vigruzki" json API.
type DumpAnswer struct {
	ArchStatus          int    `json:"a"`
	ArchSize            int    `json:"as"`
	CRC                 string `json:"crc"`
	CacheExpirationTime int    `json:"ct"`
	ID                  string `json:"id"`
	Size                int    `json:"s"`
	DbUpdateTime        int64  `json:"u"`
	UpdateTime          int64  `json:"ut"`
	UrgentUpdateTime    int64  `json:"utu"`
}

// Errors
var (
	ErrNot200HTTPCode = errors.New("not 200 HTTP code")
	ErrEmptyAnswer    = errors.New("empty answer")
)

// GetLastDumpID - fetch last dump ID from "vigruzki".
func GetLastDumpID(ts int64, u, key string) (*DumpAnswer, error) {
	answer := make([]DumpAnswer, 0)
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/last", u), nil)
	if err != nil {
		return nil, fmt.Errorf("construct request: %w", err)
	}

	q := req.URL.Query()
	q.Add("ts", fmt.Sprintf("%d", ts))

	req.URL.RawQuery = q.Encode()
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", key))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	if resp.StatusCode != 200 {
		Debug.Printf("%s\n", resp.Body)

		return nil, fmt.Errorf("%w: %d", ErrNot200HTTPCode, resp.StatusCode)
	}

	err = json.NewDecoder(resp.Body).Decode(&answer)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	if len(answer) == 0 {
		return nil, fmt.Errorf("answers: %w", ErrEmptyAnswer)
	}

	return &answer[0], nil
}

// FetchDump - fetch dump from "vigruzki".
func FetchDump(id, filename, u, key string) error {
	client := &http.Client{}
	tfn := fmt.Sprintf("%s-tmp", filename)

	out, err := os.Create(tfn)
	if err != nil {
		return err
	}

	defer out.Close()

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/get/%s", u, id), nil)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", key))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("%w: %d", ErrNot200HTTPCode, resp.StatusCode)
	}

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("body copy: %w", err)
	}

	err = os.Rename(tfn, filename)
	if err != nil {
		return fmt.Errorf("file rename: %w", err)
	}

	return nil
}

// ReadCurrentDumpID - read saved current dump id.
func ReadCurrentDumpID(filename string) (*DumpAnswer, error) {
	result := DumpAnswer{}

	if _, err := os.Stat(filename); err == nil {
		dat, err := os.ReadFile(filename)
		if err != nil {
			return &result, fmt.Errorf("read file: %w", err)
		}

		err = json.Unmarshal(dat, &result)
		if err != nil {
			return &result, fmt.Errorf("unmarshal: %w", err)
		}
	}

	return &result, nil
}

// WriteCurrentDumpID - save current dump id.
func WriteCurrentDumpID(filename string, dump *DumpAnswer) error {
	dat, err := json.Marshal(dump)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	err = os.WriteFile(filename, dat, 0644)
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// DumpUnzip - unzip dump file.
func DumpUnzip(src, filename string) error {
	tmpfilename := fmt.Sprintf("%s-temp", filename)

	r, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("open zip arch: %w", err)
	}

	defer r.Close()

	for _, f := range r.File {
		// look over file list and handle this one
		if f.Name != "dump.xml" {
			continue
		}

		if f.FileInfo().IsDir() {
			return fmt.Errorf("file is dir")
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zipped file: %w", err)
		}

		defer rc.Close()

		f, err := os.Create(tmpfilename)
		if err != nil {
			return fmt.Errorf("create tmpfile: %w", err)
		}

		defer f.Close()

		_, err = io.Copy(f, rc)
		if err != nil {
			return fmt.Errorf("write unzipped: %w", err)
		}

		break
	}

	err = os.Rename(tmpfilename, filename)
	if err != nil {
		return fmt.Errorf("file rename: %w", err)
	}

	return nil
}
