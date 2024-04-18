package main

import (
	"encoding/json"
	"fmt"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

func validate(payload []byte) ([]byte, error) {
	request := kubewarden_protocol.ValidationRequest{}
	if err := json.Unmarshal(payload, &request); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(400))
	}

	settings := Settings{}
	if err := json.Unmarshal([]byte(request.Settings), &settings); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(400))
	}

	pod := &corev1.Pod{}
	if err := json.Unmarshal([]byte(request.Request.Object), pod); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(fmt.Sprintf("Cannot decode Pod object: %s", err.Error())), kubewarden.Code(400))
	}

	for _, container := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
		if !isImageFromAllowedRepo(container.Image, settings.Repos) {
			msg := fmt.Sprintf("container <%v> has an invalid image repo <%v>, allowed repos are %v", container.Name, container.Image, settings.Repos)
			return kubewarden.RejectRequest(kubewarden.Message(msg), kubewarden.NoCode)
		}
	}

	return kubewarden.AcceptRequest()
}
