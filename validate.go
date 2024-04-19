package main

import (
	"encoding/json"
	"fmt"
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

	if !settings.HostNetwork && pod.Spec.HostNetwork {
		msg := fmt.Sprintf("The specified hostNetwork is not allowed, pod: %v. Allowed values: %v", pod.Metadata.Name, settings.HostNetwork)
		return kubewarden.RejectRequest(kubewarden.Message(msg), kubewarden.NoCode)
	}

	for _, container := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
		if settings.IsImageExempt(container.Image) {
			continue
		}

		for _, port := range container.Ports {
			if port.HostPort < settings.Min || port.HostPort > settings.Max {
				msg := fmt.Sprintf("The specified hostPort %d is not allowed, pod: %v. Allowed range: %d-%d", port.HostPort, pod.Metadata.Name, settings.Min, settings.Max)
				return kubewarden.RejectRequest(kubewarden.Message(msg), kubewarden.NoCode)
			}
		}
	}

	return kubewarden.AcceptRequest()
}
