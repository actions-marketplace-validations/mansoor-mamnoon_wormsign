# Contributing

Bug reports and focused pull requests are welcome.

1. Search existing issues before opening a new one.
2. For detections, include a public source for the indicator and a harmless
   fixture that proves the rule. Never commit live malware, secrets, or private
   machine data.
3. Add an end-to-end regression test for behavior changes.
4. Run `go test -race ./...` and `go vet ./...`.
5. Keep changes small and explain false-positive risks in the pull request.

Use the false-positive and new-campaign issue templates where applicable.
Report security vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).
