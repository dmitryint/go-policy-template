package main

import (
	"encoding/json"
	"fmt"
	"strings"

	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

// Settings is the structure that describes the policy settings.
type Settings struct {
	ExemptImages []string `json:"exemptImages"`
	HostNetwork  bool     `json:"hostNetwork"`
	Min          int32    `json:"min"`
	Max          int32    `json:"max"`
}

func (s *Settings) IsImageExempt(image string) bool {
	for _, exemptImage := range s.ExemptImages {
		if strings.HasSuffix(exemptImage, "*") {
			if strings.HasPrefix(image, strings.TrimRight(exemptImage, "*")) {
				return true
			}
		} else {
			if image == exemptImage {
				return true
			}
		}
	}
	return false
}

// No special checks have to be done
func (s *Settings) Valid() (bool, error) {
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
