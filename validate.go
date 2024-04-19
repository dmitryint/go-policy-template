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

	for _, container := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
		if settings.IsImageExempt(container.Image) {
			continue
		}

		if err := checkSecurityContext(container.SecurityContext, &settings, *container.Name); err != nil {
			return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.NoCode)
		}
	}

	if pod.Spec.SecurityContext != nil {
		if !settings.FsGroup.checkID(pod.Spec.SecurityContext.FSGroup) {
			msg := fmt.Sprintf("Pod's fsGroup '%d' is not allowed", pod.Spec.SecurityContext.FSGroup)
			return kubewarden.RejectRequest(kubewarden.Message(msg), kubewarden.NoCode)
		}
	}

	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SupplementalGroups != nil {
		for _, group := range pod.Spec.SecurityContext.SupplementalGroups {
			if !settings.SupplementalGroups.checkID(group) {
				msg := fmt.Sprintf("Pod's supplementalGroup '%d' is not allowed", group)
				return kubewarden.RejectRequest(kubewarden.Message(msg), kubewarden.NoCode)
			}
		}
	}

	return kubewarden.AcceptRequest()
}

func checkSecurityContext(securityContext *corev1.SecurityContext, settings *Settings, containerName string) error {
	if securityContext == nil {
		return nil
	}

	if !settings.RunAsUser.checkID(securityContext.RunAsUser) {
		return fmt.Errorf("container %s's runAsUser '%d' is not allowed", containerName, securityContext.RunAsUser)
	}

	if !settings.RunAsGroup.checkID(securityContext.RunAsGroup) {
		return fmt.Errorf("container %s's runAsGroup '%d' is not allowed", containerName, securityContext.RunAsGroup)
	}

	return nil
}
