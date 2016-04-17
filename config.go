package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// Config contains a set of buttons
type Config struct {
	Buttons []Button
}

// Button holds some configuration for a set of Dash Buttons
type Button struct {
	Name      string
	Address   string
	Interface string
	URL       string
	Method    string
	Headers   map[string]string
	Body      map[string]string
}

// LoadConfigFromFile reads a JSON file at path and returns
// a fully populated configuration from it and an error
func LoadConfigFromFile(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	raw, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var config Config
	err = json.Unmarshal(raw, &config)
	return &config, err
}
