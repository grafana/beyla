# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActiveRecord
      # The Instrumentation class contains logic to detect and install the ActiveRecord instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('7.1')

        install do |_config|
          require_dependencies
          patch_activerecord
        end

        present do
          defined?(::ActiveRecord)
        end

        compatible do
          gem_version >= MINIMUM_VERSION
        end

        private

        def gem_version
          ::ActiveRecord.version
        end

        def require_dependencies
          require 'active_support/lazy_load_hooks'
          require_relative 'patches/querying'
          require_relative 'patches/persistence'
          require_relative 'patches/persistence_class_methods'
          require_relative 'patches/persistence_insert_class_methods'
          require_relative 'patches/transactions_class_methods'
          require_relative 'patches/validations'
          require_relative 'patches/relation_persistence'
        end

        def patch_activerecord
          ::ActiveSupport.on_load(:active_record) do
            # Modules to prepend to ActiveRecord::Base are grouped by the source
            # module that they are defined in as they are included into ActiveRecord::Base
            # Example: Patches::PersistenceClassMethods refers to https://github.com/rails/rails/blob/v7.0.0/activerecord/lib/active_record/persistence.rb#L10
            #   which is included into ActiveRecord::Base in https://github.com/rails/rails/blob/914caca2d31bd753f47f9168f2a375921d9e91cc/activerecord/lib/active_record/base.rb#L283
            ::ActiveRecord::Base.prepend(Patches::Querying)
            ::ActiveRecord::Base.prepend(Patches::Persistence)
            ::ActiveRecord::Base.prepend(Patches::PersistenceClassMethods)
            ::ActiveRecord::Base.prepend(Patches::PersistenceInsertClassMethods)
            ::ActiveRecord::Base.prepend(Patches::TransactionsClassMethods)
            ::ActiveRecord::Base.prepend(Patches::Validations)

            ::ActiveRecord::Relation.prepend(Patches::RelationPersistence)
          end
        end
      end
    end
  end
end
