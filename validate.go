package main

import (
	"encoding/json"
	"fmt"
	batchv1 "github.com/kubewarden/k8s-objects/api/batch/v1"
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

	switch validationRequest.Request.Kind.Kind {
	case "CronJob":
		var cronJob batchv1.CronJob
		if err := json.Unmarshal([]byte(validationRequest.Request.Object), &cronJob); err != nil {
			return kubewarden.RejectRequest(kubewarden.Message(fmt.Sprintf("Cannot decode CronJob object: %s", err.Error())), kubewarden.Code(400))
		}
		if cronJob.Spec.JobTemplate.Spec.TTLSecondsAfterFinished < settings.TtlSecondsAfterFinished {
			msg := fmt.Sprintf("CronJob '%s' has ttlSecondsAfterFinished value '%d' which is less than the required minimum '%d'", cronJob.Metadata.Name, cronJob.Spec.JobTemplate.Spec.TTLSecondsAfterFinished, settings.TtlSecondsAfterFinished)
			return kubewarden.RejectRequest(kubewarden.Message(msg), kubewarden.NoCode)
		}
	case "Job":
		var job batchv1.Job
		if err := json.Unmarshal([]byte(validationRequest.Request.Object), &job); err != nil {
			return kubewarden.RejectRequest(kubewarden.Message(fmt.Sprintf("Cannot decode Job object: %s", err.Error())), kubewarden.Code(400))
		}
		if job.Spec.TTLSecondsAfterFinished < settings.TtlSecondsAfterFinished {
			msg := fmt.Sprintf("CronJob '%s' has ttlSecondsAfterFinished value '%d' which is less than the required minimum '%d'", job.Metadata.Name, job.Spec.TTLSecondsAfterFinished, settings.TtlSecondsAfterFinished)
			return kubewarden.RejectRequest(kubewarden.Message(msg), kubewarden.NoCode)
		}
	}

	return kubewarden.AcceptRequest()
}
