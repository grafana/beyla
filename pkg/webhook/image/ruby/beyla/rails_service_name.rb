# frozen_string_literal: true

module Beyla
  module OpenTelemetry
    class RailsServiceName
      MAX_APPLICATION_BYTES = 64 * 1024
      Detection = Struct.new(:name, :source, keyword_init: true)

      def self.detect(root: Bundler.root.to_s, cwd: Dir.pwd)
        new(root, cwd).detect
      end

      def initialize(root, cwd)
        @root = File.expand_path(root)
        @cwd = File.expand_path(cwd)
      end

      def detect
        project = find_project
        return unless project

        name = application_name(project)
        return Detection.new(name:, source: :application_class) if name

        name = directory_name(project)
        Detection.new(name:, source: :project_directory) if name
      end

      private

      def find_project
        return unless within_root?(@cwd)

        directory = @cwd
        loop do
          return directory if rails_project?(directory)
          return if directory == @root

          directory = File.dirname(directory)
        end
      end

      def rails_project?(directory)
        config = File.lstat(File.join(directory, 'config'))
        return false if config.symlink? || !config.directory?

        application = File.lstat(File.join(directory, 'config', 'application.rb'))
        !application.symlink? && application.file?
      rescue Errno::ENOENT
        false
      end

      def application_name(project)
        path = File.join(project, 'config', 'application.rb')
        return if File.size(path) > MAX_APPLICATION_BYTES

        RailsApplicationName.parse(File.binread(path))
      end

      def directory_name(project)
        name = File.basename(project)
        name if valid_name?(name)
      end

      def valid_name?(name)
        !name.empty? && !%w[. .. - /].include?(name) && !name.match?(/[[:cntrl:]]/)
      end

      def within_root?(path)
        @root == File::SEPARATOR || path == @root || path.start_with?("#{@root}#{File::SEPARATOR}")
      end
    end

    class RailsApplicationName
      MODULE_DECLARATION = /^\s*module\s+(?:::)?([A-Z][A-Za-z\d_]*(?:::[A-Z][A-Za-z\d_]*)*)\s*(?:#.*)?$/
      APPLICATION_DECLARATION = /^\s*class\s+((?:::)?[A-Z][A-Za-z\d_]*(?:::[A-Z][A-Za-z\d_]*)*)\s*<\s*(?:::)?Rails::Application\b/
      SCOPE_DECLARATION = /^(?:class|def|if|unless|case|while|until|for|begin)\b/
      DO_BLOCK = /\bdo(?:\s*\|[^|]*\|)?\s*(?:#.*)?$/
      SCOPE_END = /^end(?:\s*#.*)?$/

      def self.parse(source)
        new(source).parse
      end

      def initialize(source)
        @source = source
        @scopes = []
        @application_name = nil
        @application_count = 0
      end

      def parse
        @source.each_line do |line|
          return if invalid_nested_module?(line)
          next if add_module_scope(line)

          capture_application(line)
          update_scopes(line)
        end
        @application_name if @application_count == 1
      end

      private

      def invalid_nested_module?(line)
        MODULE_DECLARATION.match?(line) && @application_count.zero? && @scopes.any? { |scope| scope }
      end

      def add_module_scope(line)
        match = MODULE_DECLARATION.match(line)
        return false unless match

        @scopes << match[1]
        true
      end

      def capture_application(line)
        match = APPLICATION_DECLARATION.match(line)
        return unless match

        @application_count += 1
        @application_name = application_name(match[1]) if @application_count == 1
      end

      def application_name(class_name)
        class_name = class_name.delete_prefix('::')
        unless class_name == 'Application'
          return unless @scopes.all?

          return normalize(class_name)
        end
        return unless @scopes.length == 1 && @scopes.first

        normalize(@scopes.first)
      end

      def update_scopes(line)
        line = line.strip
        return if line.empty? || line.start_with?('#')

        if SCOPE_END.match?(line)
          @scopes.pop
        elsif SCOPE_DECLARATION.match?(line) || DO_BLOCK.match?(line)
          @scopes << nil
        end
      end

      def normalize(class_name)
        class_name
          .delete_suffix('::Application')
          .split('::')
          .map { |part| normalize_part(part) }
          .join('/')
      end

      def normalize_part(part)
        part
          .gsub(/([A-Z\d]+)([A-Z][a-z])/, '\\1_\\2')
          .gsub(/([a-z\d])([A-Z])/, '\\1_\\2')
          .tr('_', '-')
          .downcase
      end
    end
  end
end
