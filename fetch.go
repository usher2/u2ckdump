package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
)

type TDumpAnswer struct {
	ArchStatus          int    `json:"a"`
	ArchSize            int    `json:"as"`
	CRC                 string `json:"crc"`
	CacheExpirationTime int    `json:"ct"`
	Id                  string `json:"id"`
	Size                int    `json:"s"`
	DbUpdateTime        int64  `json:"u"`
	UpdateTime          int64  `json:"ut"`
	UrgentUpdateTime    int64  `json:"utu"`
}

func GetLastDumpId(ts int64, url, key string) (*TDumpAnswer, error) {
	var dump *TDumpAnswer
	answer := make([]TDumpAnswer, 0)
	client := &http.Client{}
	_url := fmt.Sprintf("%s/last", url)
	_auth := fmt.Sprintf("Bearer %s", key)
	_time := fmt.Sprintf("%d", ts)
	req, err := http.NewRequest("GET", _url, nil)
	if err != nil {
		return dump, err
	}
	q := req.URL.Query()
	q.Add("ts", _time)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Authorization", _auth)
	resp, err := client.Do(req)
	if err != nil {
		return dump, err
	}
	if resp.StatusCode != 200 {
		fmt.Printf("%s\n", resp.Body)
		return dump, fmt.Errorf("Not 200 HTTP code: %d", resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(&answer)
	if err != nil {
		return dump, err
	}
	if len(answer) == 0 {
		dump = &TDumpAnswer{}
		return dump, nil
	}
	dump = &answer[0]
	return dump, nil
}

func FetchDump(id, filename, url, key string) error {
	client := &http.Client{}
	_url := fmt.Sprintf("%s/get/%s", url, id)
	_tmpfilename := fmt.Sprintf("%s-tmp", filename)
	_auth := fmt.Sprintf("Bearer %s", key)
	out, err := os.Create(_tmpfilename)
	if err != nil {
		return err
	}
	defer out.Close()
	req, err := http.NewRequest("GET", _url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", _auth)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Not 200 HTTP code: %d", resp.StatusCode)
	}
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	err = os.Rename(_tmpfilename, filename)
	if err != nil {
		return err
	}
	return nil
}

func ReadCurrentDumpId(filename string) (*TDumpAnswer, error) {
	result := TDumpAnswer{}
	if _, err := os.Stat(filename); err == nil {
		dat, err := ioutil.ReadFile(filename)
		if err != nil {
			return &result, err
		}
		err = json.Unmarshal(dat, &result)
		if err != nil {
			return &result, err
		}
	}
	return &result, nil
}

func WriteCurrentDumpId(filename string, dump *TDumpAnswer) error {
	dat, err := json.Marshal(dump)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, dat, 0644)
	if err != nil {
		return err
	}
	return nil
}

func DumpUnzip(src, filename string) error {
	tmpfile := fmt.Sprintf("%s-temp", filename)
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if f.Name != "dump.xml" {
			continue
		}
		if f.FileInfo().IsDir() {
			return fmt.Errorf("File is dir")
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		f, err := os.Create(tmpfile)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(f, rc)
		if err != nil {
			return err
		}
	}
	err = os.Rename(tmpfile, filename)
	if err != nil {
		return err
	}
	return nil
}
