# frozen_string_literal: true

require_relative 'test_helper'
require 'beyla/rails_guard'

class RailsGuardTest < Minitest::Test
  Snapshot = Struct.new(:versions_by_name) do
    def versions(name)
      versions_by_name.fetch(name, [])
    end
  end

  def test_accepts_non_rails_application
    assert_nil rejection(nil)
  end

  def test_accepts_rails_7_1
    assert_nil rejection(snapshot('rails' => ['7.1.0'], 'railties' => ['7.1.0']))
  end

  def test_rejects_rails_7_0
    assert_match(/Rails 7\.0\.8/, rejection(snapshot('rails' => ['7.0.8'])))
  end

  def test_rejects_railties_7_0
    assert_match(/Rails 7\.0\.8/, rejection(snapshot('railties' => ['7.0.8'])))
  end

  def test_rejects_unknown_rails_version
    assert_match(/cannot be determined/, rejection(snapshot('rails' => ['7.1.0', '8.0.0'])))
  end

  def test_rejects_invalid_rails_version
    assert_match(/cannot be determined/, rejection(snapshot('rails' => ['invalid'])))
  end

  private

  def rejection(snapshot)
    Beyla::OpenTelemetry::RailsGuard.rejection(snapshot, {})
  end

  def snapshot(versions)
    Snapshot.new(versions)
  end
end
