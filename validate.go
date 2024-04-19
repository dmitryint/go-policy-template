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

	pod := &corev1.Pod{}
	if err := json.Unmarshal([]byte(validationRequest.Request.Object), pod); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(fmt.Sprintf("Cannot decode Pod object: %s", err.Error())), kubewarden.Code(400))
	}

	for _, container := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
		if container.SecurityContext != nil && container.SecurityContext.Privileged {
			msg := fmt.Sprintf("Privileged container is not allowed: %v, securityContext: %v", container.Name, container.SecurityContext)
			return kubewarden.RejectRequest(kubewarden.Message(msg), kubewarden.NoCode)
		}
	}

	return kubewarden.AcceptRequest()
}
