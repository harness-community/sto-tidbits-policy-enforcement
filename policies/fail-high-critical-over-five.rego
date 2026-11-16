package securityTests

# Block the pipeline when High + Critical findings are greater than 5.
# Attach this policy to a Policy Set: entity Security Tests, event On Step,
# action Error and exit. Reference that set from the scan step's
# Policy Enforcement setting (enforce.policySets).

deny[msg] {
  input[i].name == "output"
  critical := to_number(input[i].outcome.outputVariables.CRITICAL)
  high := to_number(input[i].outcome.outputVariables.HIGH)
  total := critical + high
  total > 5
  msg := sprintf("Fail: %d High/Critical issue(s). Threshold is 5.", [total])
}
