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

	service := &corev1.Service{}
	if err := json.Unmarshal([]byte(validationRequest.Request.Object), service); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(fmt.Sprintf("Cannot decode Service object: %s", err.Error())), kubewarden.Code(400))
	}

	if service.Spec.Type == "NodePort" {
		msg := "User is not allowed to create service of type NodePort"
		return kubewarden.RejectRequest(kubewarden.Message(msg), kubewarden.NoCode)
	}

	return kubewarden.AcceptRequest()
}
