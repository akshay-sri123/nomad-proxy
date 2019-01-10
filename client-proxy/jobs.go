package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const NomadToken = "X-Nomad-Token"

type jobPayload struct {
	Job map[string]interface{} `json:"Job"`
}

func parseJob(r *http.Request) (*jobPayload, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	b := &jobPayload{}
	if err := json.Unmarshal(body, b); err != nil {
		return nil, err
	}

	if b.Job == nil {
		return nil, fmt.Errorf("cannot parse body to Job")
	}

	return b, nil
}

// /v1/jobs overrides.
func jobs(r *http.Request) error {
	if r.Method == "GET" {
		val := r.URL.Query()
		val.Set("prefix", *jobPrefix)
		r.URL.RawQuery = val.Encode()
		return nil
	}

	if r.Method == http.MethodDelete {
		return nil
	}

	b, err := parseJob(r)
	if err != nil {
		return err
	}

	jID := b.Job["ID"].(string)
	if !strings.HasPrefix(jID, *jobPrefix) {
		b.Job["ID"] = fmt.Sprintf("%v_%v", *jobPrefix, b.Job["ID"])
	}

	b.Job["Name"] = b.Job["ID"]
	createAlerts(b)
	if err := newBody(r, &b); err != nil {
		return err
	}

	return nil
}
