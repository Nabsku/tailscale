# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause

# Offline policy and shell checks. Docker is replaced by a local stub.
require 'digest'
require 'json'
require 'open3'
require 'tmpdir'
require 'yaml'

def check(condition, message)
  abort message unless condition
end

path = File.expand_path('../workflows/mullvad-channel.yml', __dir__)
check(File.file?(path), 'Missing manual Mullvad channel workflow')
workflow = YAML.safe_load_file(path)
# Psych uses YAML 1.1, where the unquoted Actions key "on" is a boolean.
trigger = workflow.fetch('on') { workflow.fetch(true) }
check(trigger.keys == ['workflow_dispatch'], 'Only manual dispatch may trigger this workflow')
check(trigger.fetch('workflow_dispatch').fetch('inputs') == {
  'confirmation' => {
    'description' => 'After separate publication approval, enter publish-mullvad',
    'required' => true, 'type' => 'string'
  }
}, 'Require explicit publication confirmation; do not accept an arbitrary source')
check(workflow.fetch('permissions') == {}, 'Workflow permissions must default to none')
check(workflow.fetch('jobs').keys == ['promote'], 'Do not add ungated publishing jobs')
job = workflow.fetch('jobs').fetch('promote')
expected_guard = "github.event_name == 'workflow_dispatch' && " \
                 "github.repository == 'Nabsku/tailscale' && " \
                 "github.ref == 'refs/heads/main' && " \
                 "vars.MULLVAD_CHANNEL_PUBLISH_ENABLED == 'true' && " \
                 "inputs.confirmation == 'publish-mullvad'"
check(job.fetch('if').split.join(' ') == expected_guard, 'Keep every manual/main/owner/opt-in gate')
check(job.fetch('permissions') == { 'packages' => 'write' }, 'Only the gated job may write packages')
check(job.fetch('runs-on') == 'ubuntu-24.04', 'Use the hosted runner with Buildx already installed')
check(workflow.fetch('concurrency') == {
  'group' => 'mullvad-channel-publish', 'cancel-in-progress' => false
}, 'Serialize promotions without cancelling a registry write')
source = 'ghcr.io/nabsku/tailscale@sha256:f1594058f5a1c3b61bd9da683925676a200f785951f4d5eaa9859d27afcb8dc3'
channel = 'ghcr.io/nabsku/tailscale:mullvad'
check(job.fetch('env') == { 'SOURCE' => source, 'CHANNEL' => channel }, 'Use only the reviewed Mullvad digest and alias')
steps = job.fetch('steps')
check(steps.length == 2, 'Only registry login and manifest promotion are needed')
login, promotion = steps
check(login.fetch('uses').match?(%r{\Adocker/login-action@[0-9a-f]{40}\z}), 'Pin the supported login action')
check(login.fetch('with') == {
  'registry' => 'ghcr.io', 'username' => '${{ github.actor }}',
  'password' => '${{ secrets.GITHUB_TOKEN }}'
}, 'Use the job token and the login action default logout, not custom credentials')
check(promotion.fetch('shell') == 'bash', 'Use Bash error and pipeline handling')
script = promotion.fetch('run')
check(!script.include?('${{'), 'Do not interpolate dispatch input into the shell')
_, syntax_error, syntax_status = Open3.capture3('bash', '-n', stdin_data: script)
check(syntax_status.success?, syntax_error)

Dir.mktmpdir('mullvad-channel-test') do |dir|
  fixture = '{"test":"manifest bytes"}'
  fixture_source = "ghcr.io/nabsku/tailscale@sha256:#{Digest::SHA256.hexdigest(fixture)}"
  File.write(File.join(dir, 'docker'), <<~'RUBY')
    #!/usr/bin/env ruby
    require 'json'
    File.open(ENV.fetch('CALLS'), 'a') { |f| f.puts(JSON.generate(ARGV)) }
    case ARGV
    when ['buildx', 'imagetools', 'create', '--prefer-index=false', '--tag', ENV.fetch('CHANNEL'), ENV.fetch('SOURCE')]
      exit 23 if ENV['SCENARIO'] == 'create-error'
    when ['buildx', 'imagetools', 'inspect', '--raw', ENV.fetch('CHANNEL')]
      exit 29 if ENV['SCENARIO'] == 'inspect-error'
      print(ENV['SCENARIO'] == 'digest-mismatch' ? '{}' : ENV.fetch('MANIFEST'))
    else
      abort 'Unexpected Docker command; image operations are forbidden in this check'
    end
  RUBY
  File.chmod(0o755, File.join(dir, 'docker'))
  create = ['buildx', 'imagetools', 'create', '--prefer-index=false', '--tag', channel, fixture_source]
  inspect = ['buildx', 'imagetools', 'inspect', '--raw', channel]
  %w[success create-error inspect-error digest-mismatch].each do |scenario|
    calls = File.join(dir, "#{scenario}.jsonl")
    env = { 'PATH' => "#{dir}:#{ENV.fetch('PATH')}", 'CALLS' => calls, 'SCENARIO' => scenario,
            'SOURCE' => fixture_source, 'CHANNEL' => channel, 'MANIFEST' => fixture }
    _, error, status = Open3.capture3(env, 'bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', script)
    check(status.success? == (scenario == 'success'), "#{scenario}: unexpected status #{status.exitstatus}: #{error}")
    actual_calls = File.readlines(calls).map { |line| JSON.parse(line) }
    check(actual_calls == (scenario == 'create-error' ? [create] : [create, inspect]), "#{scenario}: unexpected registry commands")
    puts "PASS #{scenario} (Docker stub only)"
  end
end
puts 'PASS manual gates, fixed source, permissions, action pin, and Bash syntax'
