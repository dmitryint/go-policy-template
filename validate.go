package main

import (
	"encoding/json"
	"fmt"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

func validate(payload []byte) ([]byte, error) {
	validationRequest := kubewarden_protocol.ValidationRequest{}
	if err := json.Unmarshal(payload, &validationRequest); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(err.Error()), kubewarden.Code(400))
	}

	var resource map[string]interface{}
	if err := json.Unmarshal([]byte(validationRequest.Request.Object), &resource); err != nil {
		return kubewarden.RejectRequest(kubewarden.Message(fmt.Sprintf("Cannot decode resource: %s", err.Error())), kubewarden.Code(400))
	}

	kind := validationRequest.Request.Kind.Kind
	spec, found := resource["spec"].(map[string]interface{})
	if !found {
		return kubewarden.RejectRequest(kubewarden.Message(fmt.Sprintf("%v does not have a spec field", kind)), kubewarden.NoCode)
	}

	serviceAccountName, found := spec["serviceAccountName"].(string)
	if !found || serviceAccountName == "" {
		msg := fmt.Sprintf("%v must specify 'spec.serviceAccountName' value", kind)
		return kubewarden.RejectRequest(kubewarden.Message(msg), kubewarden.NoCode)
	}

	return kubewarden.AcceptRequest()
}
