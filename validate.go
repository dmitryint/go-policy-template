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

	pod := &corev1.Pod{}
	if err := json.Unmarshal([]byte(validationRequest.Request.Object), pod); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(fmt.Sprintf("Cannot decode Pod object: %s", err.Error())), kubewarden.Code(400))
	}

	for _, container := range pod.Spec.Containers {
		if strings.HasSuffix(container.Image, ":latest") {
			msg := "Images with the tag \"latest\" are prohibited"
			return kubewarden.RejectRequest(kubewarden.Message(msg), kubewarden.NoCode)
		}
	}

	return kubewarden.AcceptRequest()
}
