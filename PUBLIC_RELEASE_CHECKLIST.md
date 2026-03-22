# Public Release Checklist

## Release target

- Recommended version tag: `v0.1.0`
- Current CLI version: `0.1.0`

## README

- [x] Product definition is visible at the top
- [x] CAST vs SAST messaging is explicit
- [x] Cencurity Engine is named as the primary product
- [x] Tiered architecture is documented
- [x] Demo scenarios are documented
- [x] Finding taxonomy is documented
- [x] Quickstart flow is documented
- [x] Markdown renders cleanly

## Command validation

Validated in the current workspace:

- [x] `go run ./cmd/cast version`
- [x] `go run ./cmd/cast doctor`
- [x] `go test ./...`
- [x] `go build ./...`

## Demo packaging

- [x] Capture-ready scenario list added to README
- [ ] Record GIFs or screenshots for the five core scenarios
- [ ] Add final images to README or GitHub release page

## GitHub release prep

- [x] Release notes draft prepared
- [ ] Create git tag `v0.1.0`
- [ ] Publish GitHub release description from release notes draft
- [ ] Add repository topics and short description on GitHub

## Notes

This workspace is not currently attached to a Git repository, so the actual tag creation step cannot be executed here. The recommended first public tag is `v0.1.0`.
