package main

import (
	"encoding/json"
	"testing"

	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

func Test_AllowedRepos(t *testing.T) {
	settings := Settings{
		Repos: []string{"allowed/repo"},
	}

	pod := corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "container",
					Image: "allowed/repo/image:tag",
				},
			},
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequest(&pod, &settings)
	if err != nil {
		t.Fatalf("Building validation request failed: %v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Fatalf("Validating payload failed: %v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Fatalf("Unmarshaling response failed: %v", err)
	}

	if !response.Accepted {
		t.Errorf("Pod with allowed repo was rejected: %s", *response.Message)
	}
}

func Test_DisallowedRepos(t *testing.T) {
	settings := Settings{
		Repos: []string{"allowed/repo"},
	}

	pod := corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "container",
					Image: "disallowed/repo/image:tag",
				},
			},
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequest(&pod, &settings)
	if err != nil {
		t.Fatalf("Building validation request failed: %v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Fatalf("Validating payload failed: %v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Fatalf("Unmarshaling response failed: %v", err)
	}

	if response.Accepted {
		t.Error("Pod with disallowed repo was accepted")
	}
}
