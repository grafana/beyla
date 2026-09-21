# frozen_string_literal: true

require_relative 'beyla/runtime_guard'

unless Beyla::OpenTelemetry::RuntimeGuard.disabled?(ENV)
  require_relative 'beyla/log_prefix'

  reason = Beyla::OpenTelemetry::RuntimeGuard.rejection(RUBY_ENGINE, RUBY_VERSION)
  if reason
    warn "#{Beyla::OpenTelemetry::Log::PREFIX} #{reason}"
  else
    begin
      require_relative 'beyla/boot'
      Beyla::OpenTelemetry::Boot.run(File.dirname(__FILE__), __FILE__)
    rescue StandardError, ScriptError => e
      warn "#{Beyla::OpenTelemetry::Log::PREFIX} initialization failed: #{e.message}"
    end
  end
end
