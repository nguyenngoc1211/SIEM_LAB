# Rules

The active SOC Attack Scenarios v2 rules are maintained in
`../../sensor/local.rules`. They deliberately do not inspect scenario IDs,
run IDs, or the ground-truth marker URI. At startup, this custom file is
combined into a separate runtime ruleset; the cached ET Rules file is not
patched or overwritten.
