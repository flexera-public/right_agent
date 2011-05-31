module RightScale
  module BundlerSupport
    VERSION = '1.0.10'
    BUNDLE_PATH_REGEX = /BUNDLE_PATH: (.*)/
    SYSTEM_BUNDLE = false
    
    require 'rubygems'

    @@activated  = false
    @@suppressed = false
    @@basedir    = nil
    
    def self.activate
      begin
        gem 'bundler', VERSION
      rescue LoadError => e
        #no-op; if Bundler legitimately failed to activate, the require, below, will fail
      end

      require 'bundler'

      unless Bundler::VERSION == VERSION
        puts "** This application is intended to use Bundler #{VERSION} but is forced to use"
        puts "** #{Bundler::VERSION} because it was already activated . This is probably"
        puts "** harmless, but if you experience problems, please keep this issue in mind."
      end

      return true if @@activated
      ENV["BUNDLE_GEMFILE"] = File.join(self.basedir, 'Gemfile')      
      require "bundler/setup"
      @@activated = true
      return true
    end

    def self.suppress_environment(&block)
      return Bundler.with_clean_env(&block)
    end

    def self.rails_env
      if defined?(RAILS_ENV)
        RAILS_ENV
      elsif ENV['RAILS_ENV']
        ENV['RAILS_ENV']
      else
        'development'
      end
    end

    def self.basedir
      unless @@basedir
        old_loc = nil
        loc     = File.dirname(__FILE__)
        while !File.exist?(File.join(loc, 'Gemfile')) && (old_loc != loc)
          loc = File.expand_path('..', loc)
        end

        if (old_loc == loc)
          raise Errno::ENOENT, "Unable to determine Gemfile location relative to #{__FILE__}" unless File.exist?(gemfile)
        else
          @@basedir = loc
        end
      end
      
      return @@basedir
    end

    def self.is_windows?
      !!(RUBY_PLATFORM =~ /mswin/)
    end

    def self.bundle_path
      # Use the existing Bundler-defined bundle path, if it exists
      bundle_config = File.read(File.join(basedir, '.bundle', 'config')) rescue nil
      match = BUNDLE_PATH_REGEX.match(bundle_config)
      bundle_path ||= match[1] if match

      # Check for a Capistrano-style deployment and use a bundle path under
      # the shared dir
      capistrano_shared = File.expand_path(File.join(basedir, '..', '..', 'shared'))
      if File.directory?(capistrano_shared)
        bundle_path ||= File.join(capistrano_shared, 'bundle')
      end

      # Meta has an odd deployment dir structure; accommodate it.
      if ENV['RAILS_ENV'] == 'meta'
        bundle_path ||= File.expand_path(File.join(basedir, '..', 'bundle'))
      end

      user_home = ENV['HOME']

      # Our continuous integration boxes checkout Git repositories into a
      # directory named 'work.' Check for this condition in order to avoid
      # having all CI projects share the same bundle path.
      basedir_name = File.basename(basedir)
      if user_home && basedir_name == 'work'
        ci_root_dir = File.expand_path(File.join(basedir, '..'))
        bundle_path ||= File.join(user_home, '.rightscale_bundle', File.basename(ci_root_dir))
      end

      # Check for a developer system and use a bundle path under a hidden
      # dir in the user's home.
      if user_home && File.directory?(user_home)
        bundle_path ||= File.join(user_home, '.rightscale_bundle', File.basename(basedir))
      end

      raise NotFound, "Can't infer bundle path!" unless bundle_path
      return bundle_path
    end

    def self.command_line_for(action, options={})
      case action
        when :install
          base = [ "install" ]

          if ['staging', 'production', 'meta'].include?(rails_env)
            base = base + ['--without=test', '--frozen']
          else
            base = base + ['--without=deployment']
          end

          if SYSTEM_BUNDLE
            base = base + [ "--system" ]
          else
            base += ["--path", bundle_path]
          end

          base << '--quiet' if options[:quiet]

          return base.join ' '
        when :update
          base = [ "update" ]

          raise ArgumentError, "Must specify specific gems to update!" unless options[:gems]
          options[gems].each do |gem|
            base << gem
          end

          base << '--quiet' if options[:quiet]

          return base.join ' '
        else
          raise ArgumentError, "Don't know how to generate Bundler command line for #{action}"
      end
    end
  end
end
