package main

import (
	"encoding/json"
	"fmt"
	networkingv1 "github.com/kubewarden/k8s-objects/api/networking/v1"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"strings"
)

func validate(payload []byte) ([]byte, error) {
	validationRequest := kubewarden_protocol.ValidationRequest{}
	if err := json.Unmarshal(payload, &validationRequest); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(400))
	}

	ingress := &networkingv1.Ingress{}
	if err := json.Unmarshal([]byte(validationRequest.Request.Object), ingress); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(fmt.Sprintf("Cannot decode Ingress object: %s", err.Error())), kubewarden.Code(400))
	}

	for _, rule := range ingress.Spec.Rules {
		if rule.Host == "" || strings.Contains(rule.Host, "*") {
			msg := fmt.Sprintf("Hostname '%s' is not allowed since it counts as a wildcard, which can be used to intercept traffic from other applications.", rule.Host)
			return kubewarden.RejectRequest(kubewarden.Message(msg), kubewarden.NoCode)
		}
	}

	return kubewarden.AcceptRequest()
}
