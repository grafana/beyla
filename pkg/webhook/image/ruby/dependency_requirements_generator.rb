# frozen_string_literal: true

require 'bundler'
require 'rubygems'

module DependencyRequirementsGenerator
  EXCLUDED_GEMS = ['rake'].freeze
  OPENTELEMETRY_API = 'opentelemetry-api'

  module_function

  def generate(specs)
    requirements = Hash.new { |values, name| values[name] = [] }

    specs.each do |spec|
      dependencies(spec).each do |dependency|
        next if excluded?(dependency.name)

        dependency_constraints = constraints(dependency.requirement)
        requirements[dependency.name].concat(dependency_constraints) unless dependency_constraints.empty?
      end
    end

    requirements.sort.to_h.transform_values { |values| values.uniq.sort }
  end

  def from_lockfile(path)
    generate(specs_from_lockfile(path))
  end

  def opentelemetry_api_requirements(specs)
    specs.flat_map { |spec| dependencies(spec) }
         .select { |dependency| dependency.name == OPENTELEMETRY_API }
         .flat_map { |dependency| constraints(dependency.requirement) }
         .uniq.sort
  end

  def opentelemetry_api_requirements_from_lockfile(path)
    opentelemetry_api_requirements(specs_from_lockfile(path))
  end

  def render(requirements, api_requirements)
    entries = requirements.map do |name, values|
      "        #{name.inspect} => #{values.inspect},"
    end.join("\n")

    <<~RUBY
      # frozen_string_literal: true

      module Beyla
        module OpenTelemetry
          module Compatibility
            DEPENDENCY_REQUIREMENTS = {
      #{entries}
            }.freeze
            OPENTELEMETRY_API_REQUIREMENTS = #{api_requirements.inspect}.freeze
          end
        end
      end
    RUBY
  end

  def write(lockfile, output)
    specs = specs_from_lockfile(lockfile)
    requirements = generate(specs)
    api_requirements = opentelemetry_api_requirements(specs)
    File.write(output, render(requirements, api_requirements))
  end

  def dependencies(spec)
    return spec.runtime_dependencies if spec.respond_to?(:runtime_dependencies)

    spec.dependencies
  end

  def excluded?(name)
    EXCLUDED_GEMS.include?(name) || name == 'opentelemetry' || name.start_with?('opentelemetry-')
  end

  def constraints(requirement)
    requirement.requirements.reject { |operator, version| operator == '>=' && version == Gem::Version.new(0) }
               .map { |operator, version| "#{operator} #{version}" }
  end

  def specs_from_lockfile(path)
    Bundler::LockfileParser.new(File.read(path)).specs
  end
end

if $PROGRAM_NAME == __FILE__
  lockfile, output = ARGV
  abort "usage: ruby #{File.basename(__FILE__)} GEMFILE_LOCK OUTPUT" unless lockfile && output

  DependencyRequirementsGenerator.write(lockfile, output)
end
