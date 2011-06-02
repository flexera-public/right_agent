#
# Copyright (c) 2009-2011 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# This file may get required twice on Windows: once using long path and once
# using short path. Since this is where we define the File.normalize_path
# method to alleviate this issue, we have a chicken & egg problem. So detect if
# we already required this file and skip the rest if that was the case.
unless defined?(RightScale::Platform)

# Note that the platform-specific submodules will be loaded on demand to resolve
# some install-time gem dependency issues.

require 'rubygems'
require 'rbconfig'

# Load ruby interpreter monkey-patches first (to ensure File.normalize_path is defined, etc.).
require File.expand_path(File.join(File.dirname(__FILE__), 'monkey_patches', 'ruby_patch'))

module RightScale

  # A utility class that provides information about the platform on which the RightAgent is running
  # Available information includes:
  #  - which flavor cloud (EC2, Rackspace, Eucalyptus, ..)
  #  - which flavor operating system (Linux, Windows or Mac)
  #  - which OS release (a numeric value that is specific to the OS)
  #  - directories in which various bits of RightScale state may be found
  #  - platform-specific information such as Linux flavor or release
  #
  # For platform information only used in specific contexts, the dispatch method may be used
  #
  # This is a summary of the information you can query by calling Platform's instance methods:
  #  - .flavor
  #  - .release
  #  - .linux?
  #  - .mac?
  #  - .windows?
  #  - .ec2?
  #  - .rackspace?
  #  - .eucalyptus?
  #  - .filesystem
  #     - right_scale_state_dir
  #     - spool_dir
  #     - cache_dir
  #  - .linux (only available under Linux)
  #     - ubuntu?
  #     - centos?
  #     - suse?
  class Platform

    include Singleton

    # Generic platform family
    #
    # === Return
    # family(Symbol):: One of :linux, :windows or :darwin
    def family
      @family ||= case RbConfig::CONFIG['host_os']
                  when /mswin|win32|dos|mingw|cygwin/i then :windows
                  when /darwin/i then :darwin
                  when /linux/i then :linux
                  end
    end

    # Is current platform linux?
    #
    # === Return
    # true:: If current platform is linux
    # false:: Otherwise
    def linux?
      return family == :linux
    end

    # Is current platform darwin?
    #
    # === Return
    # true:: If current platform is darwin
    # false:: Otherwise
    def darwin?
      return family == :darwin
    end
    # Is current platform windows?
    #
    # === Return
    # true:: If current platform is Windows
    # false:: Otherwise
    def windows?
      return family == :windows
    end

    # Call platform specific implementation of method whose symbol is returned
    # by the passed in block. Arguments are passed through.
    # e.g.
    #
    #   Platform.dispatch(2) { :echo }
    #
    # will result in 'echo_linux(2)' being executed in self if running on linux,
    # 'echo_windows(2)' if running on Windows and 'echo_darwin(2)' if on Mac OS X.
    # Note that the method is run in the instance of the caller.
    #
    # === Parameters
    # args:: Pass-through arguments
    #
    # === Block
    # Given block should not take any argument and return a symbol for the
    # method that should be called
    #
    # === Return
    # res(Object):: Result returned by platform specific implementation
    def dispatch(*args, &blk)
      raise "Platform.dispatch requires a block" unless blk
      binding = blk.binding.eval('self')
      meth = blk.call
      target = dispatch_candidates(meth).detect do |candidate|
        binding.respond_to?(candidate)
      end
      raise "No platform dispatch target found in #{binding.class} for " +
            "'#{meth.inspect}', tried " + dispatch_candidates(meth).join(', ') unless target
      binding.__send__(target, *args)
    end

    # Load platform specific implementation
    #
    # === Return
    # true:: Always return true
    def load_platform_specific
      if linux?
        require_linux
      elsif darwin?
        require_darwin
      elsif windows?
        require_windows
      else
        raise PlatformError.new('Unknown platform')
      end
    end

    # Are we in an EC2 cloud?
    #
    # === Return
    # true:: If machine is located in an Ec2 cloud
    # false:: Otherwise
    def ec2?
      resolve_cloud_type if @ec2.nil?
      @ec2
    end

    # Are we in a Rackspace cloud?
    #
    # === Return
    # true:: If machine is located in an Rackspace cloud
    # false:: Otherwise
    def rackspace?
      resolve_cloud_type if @rackspace.nil?
      @rackspace
    end

    # Are we in a Eucalyptus cloud?
    #
    # === Return
    # true:: If machine is located in an Eucalyptus cloud
    # false:: Otherwise
    def eucalyptus?
      resolve_cloud_type if @eucalyptus.nil?
      @eucalyptus
    end

    # Controller object
    #
    # === Return
    # (Controller):: Platform-specific controller object
    def controller
      platform_service(:controller)
    end

    # Filesystem config object
    #
    # === Return
    # (Filesystem):: Platform-specific filesystem config object
    def filesystem
      platform_service(:filesystem)
    end

    # Shell information object
    #
    # === Return
    # (Object):: Platform-specific shell information object
    def shell
      platform_service(:shell)
    end

    # SSH information object
    #
    # === Return
    # (Object):: Platform-specific ssh object
    def ssh
      platform_service(:ssh)
    end

    # Platform random number generator (RNG) facilities.
    #
    # === Return
    # (Object):: Platform-specific RNG object
    def rng
      platform_service(:rng)
    end

    private

    # Load platform specific implementation
    def initialize
      require File.expand_path(File.join(File.dirname(__FILE__), 'platform', family.to_s))
      @filesystem = nil
      @shell      = nil
      @ssh        = nil
      @controller = nil

      @ec2        = nil
      @rackspace  = nil
      @eucalyptus = nil

      init
      
      # Note that we must defer any use of filesystem until requested because
      # Windows setup scripts attempt to use Platform before installing some
      # of the required gems. Don't attempt to call code that requires gems in
      # initialize().
    end

    def require_linux
      require File.expand_path(File.join(File.dirname(__FILE__), 'platform', 'linux'))
    end

    def require_darwin
      require File.expand_path(File.join(File.dirname(__FILE__), 'platform', 'darwin'))
    end

    def require_windows
      require File.expand_path(File.join(File.dirname(__FILE__), 'platform', 'windows'))
    end

    # Determines which cloud we're on by the cheap but simple expedient of
    # reading the RightScale cloud file
    def resolve_cloud_type
      cloud_type = File.read(File.join(self.filesystem.right_scale_state_dir, 'cloud')) rescue nil
      @ec2 = false
      @rackspace = false
      @eucalyptus = false
      case cloud_type
        when 'ec2' then ec2 = true
        when 'rackspace' then @rackspace = true
        when 'eucalyptus' then @eucalyptus = true
      end
    end

    # Retrieve platform specific service implementation
    #
    # === Parameters
    # name(Symbol):: Service name, one of :filesystem, :shell, :ssh, :controller
    #
    # === Return
    # res(Object):: Service instance
    #
    # === Raise
    # RightScale::Exceptions::PlatformError:: If the service is not known
    def platform_service(name)
      instance_var = "@#{name.to_s}".to_sym
      const_name = name.to_s.camelize

      unless res = self.instance_variable_get(instance_var)
        load_platform_specific
        if linux?
          res = Platform.const_get(const_name).new
        elsif darwin?
          res = Platform.const_get(const_name).new
        elsif windows?
          res = Platform.const_get(const_name).new
        end
      end
      return res
    end

  end # Platform

  # Initialize for current platform and cause File.normalize_path to be defined
  Platform.load_platform_specific

end # RightScale

end # Unless already defined
