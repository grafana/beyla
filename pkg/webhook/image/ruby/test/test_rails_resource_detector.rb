# frozen_string_literal: true

require_relative 'test_helper'
require 'beyla/rails_resource_detector'

class RailsResourceDetectorTest < Minitest::Test
  Detector = Beyla::OpenTelemetry::RailsResourceDetector
  ServiceName = Beyla::OpenTelemetry::RailsServiceName
  Log = Beyla::OpenTelemetry::Log

  class FakeResource
    class << self
      attr_accessor :default

      def create(attributes = {})
        new(attributes)
      end
    end

    def initialize(attributes)
      @attributes = attributes
    end

    def merge(other)
      self.class.new(@attributes.merge(other.attribute_enumerator.to_h))
    end

    def attribute_enumerator
      @attributes.each
    end
  end

  def setup
    FakeResource.default = FakeResource.create('service.name' => 'unknown_service')
  end

  def test_adds_the_detected_name_and_preserves_other_attributes
    FakeResource.default = FakeResource.create(
      'service.name' => 'unknown_service',
      'service.namespace' => 'production',
      'service.version' => '1.2.3'
    )
    upstream = FakeResource.create('cloud.region' => 'ca-central-1')

    ServiceName.stub(:detect, detection('orders')) do
      resource = merge(upstream)
      attributes = FakeResource.default.merge(resource).attribute_enumerator.to_h

      assert_equal 'orders', attributes['service.name']
      assert_equal 'production', attributes['service.namespace']
      assert_equal '1.2.3', attributes['service.version']
      assert_equal 'ca-central-1', attributes['cloud.region']
    end
  end

  def test_preserves_names_from_the_default_and_upstream_resources
    FakeResource.default = FakeResource.create('service.name' => 'configured')
    configured = merge(FakeResource.create)
    assert_equal 'configured', FakeResource.default.merge(configured).attribute_enumerator.to_h['service.name']

    FakeResource.default = FakeResource.create('service.name' => 'unknown_service')
    upstream = FakeResource.create('service.name' => 'detected')
    detected = merge(upstream)
    assert_equal 'detected', detected.attribute_enumerator.to_h['service.name']
  end

  def test_leaves_the_resource_unchanged_without_a_rails_project
    upstream = FakeResource.create('cloud.region' => 'ca-central-1')

    ServiceName.stub(:detect, nil) do
      assert_same upstream, merge(upstream)
    end
  end

  def test_bootstrap_hook_updates_the_final_provider_resource
    initializer = Module.new
    initializer.define_singleton_method(:_otel_detect_resource_from_env) do
      FakeResource.create('cloud.region' => 'ca-central-1')
    end
    initializer.define_singleton_method(:provider_resource) do
      FakeResource.default.merge(_otel_detect_resource_from_env)
    end

    ServiceName.stub(:detect, detection('orders')) do
      Log.stub(:info, nil) do
        Detector.stub(:sdk_resource, FakeResource) do
          Detector.install(initializer)
          Detector.install(initializer)
          attributes = initializer.provider_resource.attribute_enumerator.to_h

          assert_equal 'orders', attributes['service.name']
          assert_equal 'ca-central-1', attributes['cloud.region']
          assert_equal 1, initializer.singleton_class.ancestors.count(Detector::InitializerPatch)
        end
      end
    end
  end

  def test_logs_detection_method_and_selected_name
    logs = []

    ServiceName.stub(:detect, detection('orders', :project_directory)) do
      Log.stub(:info, ->(message) { logs << message }) do
        Detector.merge(FakeResource.create, resource_class: FakeResource)
      end
    end

    assert_equal [
      'service.name was not found by OpenTelemetry resource detectors; looking for a Rails service name',
      'using service.name="orders" detected from Rails project directory'
    ], logs
  end

  def test_logs_when_detection_finds_no_name
    logs = []

    ServiceName.stub(:detect, nil) do
      Log.stub(:info, ->(message) { logs << message }) do
        Detector.merge(FakeResource.create, resource_class: FakeResource)
      end
    end

    assert_equal [
      'service.name was not found by OpenTelemetry resource detectors; looking for a Rails service name',
      'Rails service name detection found no name; keeping service.name="unknown_service"'
    ], logs
  end

  def test_logs_existing_resource_detector_name
    FakeResource.default = FakeResource.create('service.name' => 'configured')
    logs = []

    Log.stub(:info, ->(message) { logs << message }) do
      Detector.merge(FakeResource.create, resource_class: FakeResource)
    end

    assert_equal ['using service.name="configured" from OpenTelemetry resource detectors'], logs
  end

  private

  def detection(name, source = :application_class)
    ServiceName::Detection.new(name:, source:)
  end

  def merge(upstream)
    Log.stub(:info, nil) do
      Detector.merge(upstream, resource_class: FakeResource)
    end
  end
end
