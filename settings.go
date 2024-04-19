package main

import (
	"encoding/json"
	"fmt"
	"regexp"

	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

// Settings is the structure that describes the policy settings.
type Settings struct {
	Labels  []Label `json:"labels"`
	Message string  `json:"message"`
}

type Label struct {
	Key          string `json:"key"`
	AllowedRegex string `json:"allowedRegex"`
}

func (s *Settings) Valid() (bool, error) {
	for _, label := range s.Labels {
		if label.Key == "" {
			return false, fmt.Errorf("label key cannot be empty")
		}
		if label.AllowedRegex != "" {
			if _, err := regexp.Compile(label.AllowedRegex); err != nil {
				return false, fmt.Errorf("invalid regex for label key '%s': %w", label.Key, err)
			}
		}
	}
	return true, nil
}

func NewSettingsFromValidationReq(validationReq *kubewarden_protocol.ValidationRequest) (Settings, error) {
	settings := Settings{}
	err := json.Unmarshal(validationReq.Settings, &settings)
	return settings, err
}

func validateSettings(payload []byte) ([]byte, error) {
	logger.Info("validating settings")

	settings := Settings{}
	err := json.Unmarshal(payload, &settings)
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}

	valid, err := settings.Valid()
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}
	if valid {
		return kubewarden.AcceptSettings()
	}

	logger.Warn("rejecting settings")
	return kubewarden.RejectSettings(kubewarden.Message("Provided settings are not valid"))
}
