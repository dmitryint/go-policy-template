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

	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			if !isHostPathAllowed(volume.HostPath, settings.AllowedHostPaths) {
				msg := fmt.Sprintf("HostPath volume %v is not allowed, pod: %v. Allowed paths: %v", volume.Name, pod.Metadata.Name, settings.AllowedHostPaths)
				return kubewarden.RejectRequest(kubewarden.Message(msg), kubewarden.NoCode)
			}
		}
	}

	return kubewarden.AcceptRequest()
}

func isHostPathAllowed(hostPath *corev1.HostPathVolumeSource, allowedPaths []AllowedHostPath) bool {
	if len(allowedPaths) == 0 {
		// If no allowedHostPaths are specified, all host paths are blocked
		return false
	}

	for _, allowed := range allowedPaths {
		if strings.HasPrefix(*hostPath.Path, allowed.PathPrefix) {
			if allowed.ReadOnly && !isVolumeReadOnly(*hostPath.Path, allowed.PathPrefix) {
				continue
			}
			return true
		}
	}

	return false
}

func isVolumeReadOnly(volumePath, pathPrefix string) bool {
	// Logic to check if the volume mount is read-only goes here
	// This function should return true if the volume mount is read-only
	// For now, we'll assume it's not implemented and return false
	return false
}
