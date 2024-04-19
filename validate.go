package main

import (
	"encoding/json"
	"fmt"
	"strings"

	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
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

	pod := &corev1.Pod{}
	if err := json.Unmarshal([]byte(validationRequest.Request.Object), pod); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(fmt.Sprintf("Cannot decode Pod object: %s", err.Error())), kubewarden.Code(400))
	}

	for _, container := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
		if settings.IsImageExempt(container.Image) {
			continue
		}

		if err := checkCapabilities(*container, &settings); err != nil {
			return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.NoCode)
		}
	}

	return kubewarden.AcceptRequest()
}

func checkCapabilities(container corev1.Container, settings *Settings) error {
	if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
		for _, cap := range container.SecurityContext.Capabilities.Add {
			if !isCapabilityAllowed(cap, settings.AllowedCapabilities) {
				return fmt.Errorf("container <%v> has a disallowed capability <%v>", container.Name, cap)
			}
		}

		for _, requiredCap := range settings.RequiredDropCapabilities {
			if !isCapabilityDropped(requiredCap, container.SecurityContext.Capabilities.Drop) {
				return fmt.Errorf("container <%v> is not dropping required capability <%v>", container.Name, requiredCap)
			}
		}
	}
	return nil
}

func isCapabilityAllowed(capability string, allowedCaps []string) bool {
	capability = strings.ToUpper(capability)
	for _, allowedCap := range allowedCaps {
		if strings.ToUpper(allowedCap) == capability || allowedCap == "*" {
			return true
		}
	}
	return false
}

func isCapabilityDropped(requiredCap string, droppedCaps []string) bool {
	requiredCap = strings.ToUpper(requiredCap)
	for _, droppedCap := range droppedCaps {
		if strings.ToUpper(droppedCap) == requiredCap || string(droppedCap) == "ALL" {
			return true
		}
	}
	return false
}
