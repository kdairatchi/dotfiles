#!/usr/bin/env bats

load '../lib/bats-support/load.bash'
load '../lib/bats-assert/load.bash'

@test "alienvault.sh --help" {
  run ./alienvault.sh --help
  assert_success
  assert_output --partial "Usage: alienvault [OPTIONS] -t <targets>"
}

@test "alienvault.sh --version" {
  run ./alienvault.sh --version
  assert_success
  assert_output --partial "alienvault v2.1.0"
}

@test "alienvault.sh --banner" {
  run ./alienvault.sh --banner
  assert_success
  assert_output --partial "KDAIRATCHI SECURITY TOOLKIT"
}

@test "alienvault.sh --dry-run" {
    run ./alienvault.sh -t <(echo "example.com") --dry-run
    assert_success
    assert_output --partial "[DRY RUN] Would fetch: https://otx.alienvault.com/api/v1/indicators/hostname/example.com/url_list?limit=500&page=1"
}