# frozen_string_literal: true

require 'bundler'

lockfile = ARGV.fetch(0)
parser = Bundler::LockfileParser.new(File.read(lockfile))
pins = parser.specs.reject { |spec| spec.source.is_a?(Bundler::Source::Git) }
pins.map { |spec| "#{spec.name}:#{spec.version}" }.uniq.sort.each { |pin| puts pin }
