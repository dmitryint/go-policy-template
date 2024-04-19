package main

import (
	"encoding/json"
	"fmt"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"regexp"
)

func validate(payload []byte) ([]byte, error) {
	validationRequest := kubewarden_protocol.ValidationRequest{}
	if err := json.Unmarshal(payload, &validationRequest); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(400))
	}

	settings, err := NewSettingsFromValidationReq(&validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(400))
	}

	var metadata metav1.ObjectMeta
	if err := json.Unmarshal([]byte(validationRequest.Request.Object), &metadata); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(fmt.Sprintf("Cannot decode object metadata: %s", err.Error())), kubewarden.Code(400))
	}

	missingLabels, err := checkRequiredLabels(metadata.Labels, settings.Labels)
	if err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.NoCode)
	}

	if len(missingLabels) > 0 {
		msg := settings.Message
		if msg == "" {
			msg = fmt.Sprintf("you must provide labels: %v", missingLabels)
		}
		return kubewarden.RejectRequest(kubewarden.Message(msg), kubewarden.NoCode)
	}

	return kubewarden.AcceptRequest()
}

func checkRequiredLabels(providedLabels map[string]string, requiredLabels []Label) ([]string, error) {
	var missingLabels []string
	for _, requiredLabel := range requiredLabels {
		value, found := providedLabels[requiredLabel.Key]
		if !found {
			missingLabels = append(missingLabels, requiredLabel.Key)
			continue
		}
		if requiredLabel.AllowedRegex != "" {
			matches, err := regexp.MatchString(requiredLabel.AllowedRegex, value)
			if err != nil {
				return nil, fmt.Errorf("failed to match regex: %w", err)
			}
			if !matches {
				return nil, fmt.Errorf("label <%v: %v> does not satisfy allowed regex: %v", requiredLabel.Key, value, requiredLabel.AllowedRegex)
			}
		}
	}
	return missingLabels, nil
}
