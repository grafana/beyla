# frozen_string_literal: true

require 'fileutils'
require 'tmpdir'
require_relative 'test_helper'
require 'beyla/rails_service_name'

class RailsServiceNameTest < Minitest::Test
  Detector = Beyla::OpenTelemetry::RailsServiceName

  def test_detects_canonical_rails_application_name
    with_project(<<~RUBY) do |root, project|
      module OrdersAPI
        class Application < Rails::Application
        end
      end
    RUBY
      detection = Detector.detect(root:, cwd: project)
      assert_equal 'orders-api', detection.name
      assert_equal :application_class, detection.source
    end
  end

  def test_normalizes_direct_and_nested_application_classes
    with_project("class Admin::BillingAPI::Application < ::Rails::Application\nend\n") do |root, project|
      assert_equal 'admin/billing-api', detect_name(root, project)
    end
  end

  def test_falls_back_to_project_directory
    with_project("Application = Class.new(Rails::Application)\n", project_name: 'orders-service') do |root, project|
      detection = Detector.detect(root:, cwd: project)
      assert_equal 'orders-service', detection.name
      assert_equal :project_directory, detection.source
    end
  end

  def test_falls_back_when_multiple_applications_are_declared
    with_project(<<~RUBY, project_name: 'orders-service') do |root, project|
      class FirstApp < Rails::Application
      end
      class SecondApp < Rails::Application
      end
    RUBY
      assert_equal 'orders-service', detect_name(root, project)
    end
  end

  def test_falls_back_for_an_application_nested_in_a_non_module_scope
    with_project(<<~RUBY, project_name: 'orders-service') do |root, project|
      class Wrapper
        class Orders < Rails::Application
        end
      end
    RUBY
      assert_equal 'orders-service', detect_name(root, project)
    end
  end

  def test_searches_parent_directories
    with_project("class Orders < Rails::Application\nend\n") do |root, project|
      cwd = File.join(project, 'tmp', 'pids')
      FileUtils.mkdir_p(cwd)

      assert_equal 'orders', detect_name(root, cwd)
    end
  end

  def test_ignores_non_rails_projects_and_paths_outside_bundle_root
    Dir.mktmpdir do |root|
      assert_nil detect_name(root, root)

      Dir.mktmpdir do |outside|
        assert_nil detect_name(root, outside)
      end
    end
  end

  def test_ignores_symlinked_config_and_application_paths
    Dir.mktmpdir do |root|
      project = File.join(root, 'orders')
      shared = File.join(root, 'shared')
      FileUtils.mkdir_p(shared)
      FileUtils.mkdir_p(project)
      File.symlink(shared, File.join(project, 'config'))
      assert_nil detect_name(root, project)

      FileUtils.rm_f(File.join(project, 'config'))
      FileUtils.mkdir_p(File.join(project, 'config'))
      target = File.join(shared, 'application.rb')
      File.write(target, "class Orders < Rails::Application\nend\n")
      File.symlink(target, File.join(project, 'config', 'application.rb'))
      assert_nil detect_name(root, project)
    end
  end

  def test_large_application_file_uses_directory_fallback
    source = "# padding\n" * (Detector::MAX_APPLICATION_BYTES / 2)
    with_project(source, project_name: 'orders') do |root, project|
      assert_equal 'orders', detect_name(root, project)
    end
  end

  private

  def detect_name(root, cwd)
    Detector.detect(root:, cwd:)&.name
  end

  def with_project(source, project_name: 'app')
    Dir.mktmpdir do |root|
      project = File.join(root, project_name)
      config = File.join(project, 'config')
      FileUtils.mkdir_p(config)
      File.write(File.join(config, 'application.rb'), source)
      yield root, project
    end
  end
end
