#!/usr/bin/env bats

@test "accept because name is not on the deny list" {
  run kwctl run annotated-policy.wasm -r test_data/pod.json --settings-json '{"repos": ["registry.k8s.io/pause"]}'
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}
