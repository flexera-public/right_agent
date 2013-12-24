#
# Copyright (c) 2009-2013 RightScale Inc
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
  require 'right_support'

  require ::File.expand_path('../exceptions', __FILE__)

  module RightScale

    # A utility class that provides information about the platform on which the
    # RightAgent is running.
    #
    # Available information includes:
    #  - which flavor cloud (EC2, Rackspace, Eucalyptus, ..)
    #  - which flavor operating system (Linux, Windows or Mac)
    #  - which OS release (a numeric value that is specific to the OS)
    #  - directories in which various bits of RightScale state may be found
    #  - platform-specific information such as Linux flavor or release
    #
    # For platform information only used in specific contexts, the dispatch
    # method may be used.
    class Platform

      include RightSupport::Ruby::EasySingleton

      # exceptions
      class CommandError < RightScale::Exceptions::PlatformError
        attr_accessor :command
        attr_accessor :status
        attr_accessor :output_text
      end

      attr_reader :flavor, :release, :codename

      # Generic platform family
      #
      # @deprecated family is a legacy definition, see genus/species for a more
      #   granular definition.
      #
      # @return [Symbol] result as one of :linux, :windows or :darwin
      def family
        warn "#{self.class.name}#family is deprecated, use genus or species instead.\n#{caller[0,2].join("\n")}"
        (genus == :unix) ? species : genus
      end

      # @return [Symbol] platform genus
      def genus
        resolve_taxonomy unless @genus
        @genus
      end

      # @return [Symbol] platform species
      def species
        resolve_taxonomy unless @species
        @species
      end

      # Is current platform in the Unix genus?
      #
      # @return [TrueClass|FalseClass] true if Unix
      def unix?
        genus == :unix
      end

      # Is current platform Linux?
      #
      # @return [TrueClass|FalseClass] true if Linux
      def linux?
        species == :linux
      end

      # Is current platform Darwin?
      #
      # @return [TrueClass|FalseClass] true if Darwin
      def darwin?
        species == :darwin
      end

      # Is current platform Windows?
      #
      # @return [TrueClass|FalseClass] true if Windows
      def windows?
        genus == :windows
      end

      # Are we on an EC2 cloud instance?
      #
      # @deprecated use right_link cloud libraries instead.
      #
      # @return [TrueClass|FalseClass] true if EC2
      def ec2?
        warn "#{self.class.name}#ec2? is deprecated, use right_link cloud libraries instead.\n#{caller[0,2].join("\n")}"
        resolve_cloud_type unless @cloud_type
        @cloud_type == 'ec2'
      end

      # Are we on an Rackspace cloud instance?
      #
      # @deprecated use right_link cloud libraries instead.
      #
      # @return [TrueClass|FalseClass] true if Rackspace
      def rackspace?
        warn "#{self.class.name}#rackspace? is deprecated, use right_link cloud libraries instead.\n#{caller[0,2].join("\n")}"
        resolve_cloud_type unless @cloud_type
        @cloud_type == 'rackspace'
      end

      # Are we on an Eucalyptus cloud instance?
      #
      # @deprecated use right_link cloud libraries instead.
      #
      # @return [TrueClass|FalseClass] true if Eucalyptus
      def eucalyptus?
        warn "#{self.class.name}#eucalyptus? is deprecated, use right_link cloud libraries instead.\n#{caller[0,2].join("\n")}"
        resolve_cloud_type unless @cloud_type
        @cloud_type == 'eucalyptus'
      end

      # Call platform specific implementation of method whose symbol is returned
      # by the passed in block. Arguments are passed through.
      # e.g.
      #
      #   Platform.dispatch(2) { :echo }
      #
      # will result in 'echo_linux(2)' being executed in self if running on
      # linux, 'echo_windows(2)' if running on Windows and 'echo_darwin(2)' if
      # on Mac OS X. Note that the method is run in the instance of the caller.
      #
      # @param [Array] args as pass-through arguments
      #
      # @yield [] given block should not take any argument and return a symbol
      #  for the method that should be called.
      #
      # @return [Object] result of Platform-specific implementation
      def dispatch(*args, &blk)
        raise 'Platform.dispatch requires a block' unless blk
        binding = blk.binding.eval('self')
        meth = blk.call
        target = dispatch_candidates(meth).detect do |candidate|
          binding.respond_to?(candidate)
        end
        raise "No platform dispatch target found in #{binding.class} for " +
              "'#{meth.inspect}', tried " + dispatch_candidates(meth).join(', ') unless target
        binding.send(target, *args)
      end

      # @return [Controller] Platform-specific controller object
      def controller
        platform_service(:controller)
      end

      # @return [Filesystem] Platform-specific filesystem config object
      def filesystem
        platform_service(:filesystem)
      end

      # @return [VolumeManager] Platform-specific volume manager config object
      def volume_manager
        platform_service(:volume_manager)
      end

      # @return [Shell] Platform-specific shell information object
      def shell
        platform_service(:shell)
      end

      # @return [Rng] Platform-specific RNG object
      def rng
        platform_service(:rng)
      end

      # @return [Process] Platform-specific process facilities object
      def process
        platform_service(:process)
      end

      # @return [Installer] Platform-specific installer information object
      def installer
        platform_service(:installer)
      end

      # Blocking call to invoke a command line tool used to perform platform-
      # specific tasks.
      #
      # Also provides a consistent interface for mocking command output during
      # spec testing. Implementations should use this method instead of
      # embedding popen/backtick calls to assist with testing.
      #
      # @param [String] command to run
      # @param [Hash] options for execution
      # @option options [TrueClass|FalseClass] :raise_on_failure true to raise on command failure (Default)
      #
      # @return [String] output from command or empty
      #
      # @raise [CommandError] on failure (by default)
      def execute(command, options = {})
        options = { :raise_on_failure => true }.merge(options)
        raise_on_failure = options[:raise_on_failure]
        output_text = ''
        begin
          output_text = `#{command}`
          if !$?.success? && options[:raise_on_failure]
            message = []
            message << "Command failed with exit code = #{$?.exitstatus}:"
            message << "> #{command}"
            error_output_text = output_text.strip
            message << error_output_text unless error_output_text.empty?
            e = CommandError.new(message.join("\n"))
            e.command = command
            e.status = $?
            e.output_text = output_text
            raise e
          end
        rescue Errno::ENOENT => e
          if raise_on_failure
            raise CommandError, "Command failed: #{e.message}"
          end
        end
        output_text
      end

      # Base class for platform helpers.
      class PlatformHelperBase

        private

        # Convenience method for declaring must-be-overridden interfaces.
        #
        # @raise [NotImplementedError] always unless overridden
        def must_be_overridden
          raise ::NotImplementedError, 'Must be overridden'
        end

        # Convenience method for executing a command via platform.
        #
        # See Platform#execute
        def execute(cmd, options = {})
          ::RightScale::Platform.execute(cmd, options)
        end
      end

      # Declares various file system APIs.
      class Filesystem < PlatformHelperBase

        # Is given command available in the PATH?
        #
        # @param [String] command_name to be tested
        #
        # @return [TrueClass|FalseClass] true if command is in path
        def has_executable_in_path(command_name)
          return !!find_executable_in_path(command_name)
        end

        # Finds the given command name in the PATH. this emulates the 'which'
        # command from linux (without the terminating newline).
        #
        # @param [String] command_name to be tested
        #
        # @return [String] path to first matching executable file in PATH or nil
        def find_executable_in_path(command_name)
          must_be_overridden
        end

        # @return [String] directory containing generated agent configuration files
        def right_agent_cfg_dir
          must_be_overridden
        end

        # @return [String] static (time-invariant) state that is common to all RightScale apps/agents
        def right_scale_static_state_dir
          must_be_overridden
        end

        # @return [String] static (time-invariant) state that is specific to RightLink
        def right_link_static_state_dir
          must_be_overridden
        end

        # @return [String] dynamic, persistent runtime state that is specific to RightLink
        def right_link_dynamic_state_dir
          must_be_overridden
        end

        # @return [String] data which is awaiting some kind of later processing
        def spool_dir
          must_be_overridden
        end

        # TEAL TODO description
        def ssh_cfg_dir
          must_be_overridden
        end

        # Cached data from applications. Such data is locally generated as a
        # result of time-consuming I/O or calculation. The application must
        # be able to regenerate or restore the data.
        #
        # @return [String] cache directory
        def cache_dir
          must_be_overridden
        end

        # @return [String] system logs
        def log_dir
          must_be_overridden
        end

        # For Unix compatibility; has no significance in Windows
        #
        # @return [String] source code directory, for reference purposes and for development
        def source_code_dir
          must_be_overridden
        end

        # @return [String] temporary files.
        def temp_dir
          must_be_overridden
        end

        # @return [String] path to place pid files
        def pid_dir
          must_be_overridden
        end

        # @return [String] installed home (parent of) right_link directory path
        def right_link_home_dir
          must_be_overridden
        end

        # @return [String] path to right link configuration and internal usage scripts
        def private_bin_dir
          must_be_overridden
        end

        # TEAL TODO description
        def sandbox_dir
          must_be_overridden
        end

        # Converts a long path (e.g. "C:/Program Files") to a short path
        # (e.g. "C:/PROGRA~1") if necessary. See implementation for notes.
        #
        # For Windows compatibility; has no significance in Linux
        #
        # @param [String] long_path to convert
        #
        # @return [String] short path
        def long_path_to_short_path(long_path)
          must_be_overridden
        end

        # Converts slashes in a path to a consistent style.
        #
        # For Windows compatibility; has no significance in Linux
        #
        # @param [String] path to make pretty
        # @param [String] native_fs_flag as true if path is pretty for native
        #   file system (i.e. file system calls more likely to succeed), false
        #   if pretty for Ruby interpreter (default).
        #
        # @return [String] pretty path
        def pretty_path(path, native_fs_flag = false)
          must_be_overridden
        end

        # Ensures a local drive location for the file or folder given by path
        # by copying to a local temp directory given by name only if the item
        # does not appear on the home drive. This method is useful because
        # secure applications refuse to run scripts from network locations, etc.
        # Replaces any similar files in given temp dir to ensure latest updates.
        #
        # For Windows compatibility; has no significance in Linux
        #
        # @param [String] path to file or directory to be placed locally
        # @param [String] temp_dir_name relative to user temp_dir to use only if the file or folder is not on a local drive
        #
        # @return [String] local drive path
        def ensure_local_drive_path(path, temp_dir_name)
          must_be_overridden
        end

        # Creates a symlink (if supported by platform).
        #
        # @param [String] from_path the path to the real file/directory
        # @param [String] to_path the path to the symlink to be created
        #
        # @return [Fixnum] always 0 as does File.symlink under Linux
        #
        # @raise [RightScale::Exceptions::PlatformError] on failure
        def create_symlink(from_path, to_path)
          must_be_overridden
        end
      end

      # Provides utilities for managing volumes (disks).
      class VolumeManager < PlatformHelperBase

        # exceptions
        class ParserError < ::RightScale::Exceptions::PlatformError; end
        class VolumeError < ::RightScale::Exceptions::PlatformError; end

        # Gets a list of currently visible volumes in the form:
        # [{:device, :label, :uuid, :type, :filesystem}]
        #
        # @param [Hash] conditions to match, if any (Default = no conditions)
        #
        # @return [Array] volume info as an array of hashes or empty
        #
        # @raise [ParserError] on failure to parse volume list
        # @raise [VolumeError] on failure to execute `blkid` to obtain raw output
        def volumes(conditions = nil)
          must_be_overridden
        end
      end # VolumeManager

      # Declares various command shell APIs.
      class Shell < PlatformHelperBase

        # @return [String] name or path of file reserved for null output redirection
        def null_output_name
          must_be_overridden
        end

        # Fully qualifies a partial script file path to ensure it is executable on
        # the current platform.
        #
        # For Windows compatibility; has no significance in Linux
        #
        # @param [String] partial_script_file_path to format
        # @param [String] default_extension to use if no extension (Default = platform specific)
        #
        # @return [String] full script path
        def format_script_file_name(partial_script_file_path, default_extension = nil)
          must_be_overridden
        end

        # Formats an executable command by quoting any of the arguments as needed
        # and building an executable command string.
        #
        # @param [String] executable_file_path full or partial
        # @param [Array] arguments for executable, if any
        #
        # @return [String] executable command string
        def format_executable_command(executable_file_path, *arguments)
          must_be_overridden
        end

        # Formats a shell command using the given script path and arguments.
        # Provides the path to the executable for the script as needed for the
        # current platform.
        #
        # @param [String] shell_script_file_path shell script file path
        # @param [Array] arguments for executable, if any
        #
        # @return [String] executable command string
        def format_shell_command(shell_script_file_path, *arguments)
          must_be_overridden
        end

        # Formats a ruby command using the given script path and arguments and
        # the sandbox ruby path.
        #
        # @param [String] shell_script_file_path for formatting
        # @param [Array] arguments for command or empty
        #
        # @return [String] executable command string
        def format_ruby_command(shell_script_file_path, *arguments)
          return format_executable_command(sandbox_ruby, [shell_script_file_path, arguments])
        end

        # Appends STDOUT redirection to the given shell command.
        #
        # @param [String] cmd to format
        # @param [String] redirection target (Default = null output)
        #
        # @return [String] formatted for redirection
        def format_redirect_stdout(cmd, target = nil)
          target ||= null_output_name
          return cmd + " 1>#{target}"
        end

        # Appends STDERR redirection to the given shell command.
        #
        # @param [String] cmd to format
        # @param [String] redirection target (Default = null output)
        #
        # @return [String] formatted for redirection
        def format_redirect_stderr(cmd, target = nil)
          target ||= null_output_name
          return cmd + " 2>#{target}"
        end

        # Appends STDERR redirection to the given shell command.
        #
        # @param [String] cmd to format
        # @param [String] redirection target (Default = null output)
        #
        # @return [String] formatted for redirection
        def format_redirect_both(cmd, target = nil)
          target ||= null_output_name
          return cmd + " 1>#{target} 2>&1"
        end

        # @return [String] full path to the RightScale sandboxed ruby executable
        def sandbox_ruby
          must_be_overridden
        end

        # Gets the current system uptime.
        #
        # @return [Float] time the machine has been up, in seconds, or 0.0
        def uptime
          must_be_overridden
        end

        # Gets the time at which the system was booted.
        #
        # @return [Integer] the UTC timestamp at which the system was booted or nil on failure
        def booted_at
          must_be_overridden
        end
      end

      # System controller APIs.
      class Controller < PlatformHelperBase

        # Reboot machine now.
        #
        # @return [TrueClass] always true
        def reboot
          must_be_overridden
        end

        # Shutdown machine now.
        #
        # @return [TrueClass] always true
        def shutdown
          must_be_overridden
        end
      end

      # Randomizer APIs.
      class Rng < PlatformHelperBase

        # Generates a pseudo-random byte string.
        #
        # @param [Fixnum] count of bytes
        #
        # @return [String] bytes
        def pseudorandom_bytes(count)
          must_be_overridden
        end
      end

      # Process APIs.
      class Process < PlatformHelperBase

        # Queries resident/working set size (total memory used by process) for
        # the process given by identifier (PID).
        #
        # @param [Fixnum] pid for query (Default = current process)
        #
        # @return [Integer] current set size in KB
        def resident_set_size(pid = nil)
          must_be_overridden
        end
      end

      # Package installation APIs.
      class Installer < PlatformHelperBase

        # exceptions
        class PackageNotFound < ::RightScale::Exceptions::PlatformError; end
        class PackageManagerNotFound < ::RightScale::Exceptions::PlatformError; end

        # @return [String] installer output or nil
        attr_accessor :output

        def initialize
          @output = nil
        end

        # Install packages based on installed package manager.
        #
        # For Unix compatibility; has no significance in Windows
        #
        # @param [Array] packages to be installed
        #
        # @return [TrueClass] always true
        #
        # @raise [RightScale::Exceptions::PlatformError] if not supported by platform
        # @raise [PackageNotFound] if package is not found
        # @raise [PackageManagerNotFound] if package manager is not available
        # @raise [CommandError] on any other command failure
        def install(packages)
          must_be_overridden
        end
      end

      private

      # Load platform specific implementation
      def initialize
        @genus      = nil
        @species    = nil
        @filesystem = nil
        @shell      = nil
        @ssh        = nil
        @controller = nil
        @installer  = nil
        @flavor     = nil
        @release    = nil
        @codename   = nil

        initialize_platform_specific
      end

      # First-initialization tasks. Also convenient for overriding during
      # testing on platforms that differ from current platform.
      def initialize_platform_specific
        load_platform_specific
        initialize_genus
        initialize_species
      end

      # Load platform specific implementation
      #
      # @return [TrueClass|FalseClass] true if loaded first time, false if already loaded
      def load_platform_specific
        # TEAL NOTE the unusal thing about this singleton is that it is
        # redefined incrementally by first loading the base then the genus then
        # the species, all of which define parts of the whole.
        result = require platform_genus_path
        result = (require platform_species_path) && result
        result
      end

      # Performs any platform genus-specific initialization. This method is
      # invoked only after the current platform's specific implementation has
      # been loaded.
      #
      # @return [TrueClass] always true
      def initialize_genus
        raise ::NotImplementedError, 'Must be overridden'
      end

      # Performs any platform species-specific initialization. This method is
      # invoked only after the current platform's specific implementation has
      # been loaded.
      #
      # @return [TrueClass] always true
      def initialize_species
        raise ::NotImplementedError, 'Must be overridden'
      end

      # Determines genus/species for current platform.
      def resolve_taxonomy
        case ::RbConfig::CONFIG['host_os']
        when /darwin/i
          @genus   = :unix
          @species = :darwin
        when /linux/i
          @genus   = :unix
          @species = :linux
        when /mingw/i
          @genus   = :windows
          @species = :mingw
        when /mswin/i
          @genus   = :windows
          @species = :mswin
        when /windows|win32|dos|cygwin/i
          raise ::RightScale::Exceptions::PlatformError,
                'Unsupported Ruby-on-Windows variant'
        else
          raise ::RightScale::Exceptions::PlatformError, 'Unknown platform'
        end
        true
      end

      # @return [String] path to platform-independent implementation.
      def platform_base_path
        ::File.expand_path('../platform', __FILE__)
      end

      # @return [String] path to platform-specific genus implementation.
      def platform_genus_path
        ::File.expand_path("#{genus}/platform", platform_base_path)
      end

      # @return [String] path to platform-specific species implementation.
      def platform_species_path
        ::File.expand_path("#{genus}/#{species}/platform", platform_base_path)
      end

      # Retrieve platform specific service implementation
      #
      # @param [Symbol] name of platform service
      #
      # @return [PlatformHelperBase] service instance
      #
      # @raise [RightScale::Exceptions::PlatformError] on unknown service
      def platform_service(name)
        instance_var = "@#{name.to_s}".to_sym
        const_name = name.to_s.camelize

        unless res = self.instance_variable_get(instance_var)
          load_platform_specific
          if clazz = Platform.const_get(const_name)
            res = clazz.new
            self.instance_variable_set(instance_var, res)
          else
            raise ::RightScale::Exceptions::PlatformError,
                  "Unknown platform service: #{name}"
          end
        end
        return res
      end

      # Determines which cloud we're on by the cheap but simple expedient of
      # reading the RightScale cloud file.
      #
      # @deprecated leverage the right_link cloud libraries for any cloud-
      #   specific behavior because the behavior of all possible clouds is
      #   beyond the scope of hard-coded case statements.
      #
      # @return [String] cloud type or nil
      def resolve_cloud_type
        cloud_file_path = ::File.join(self.filesystem.right_scale_static_state_dir, 'cloud')
        @cloud_type = ::File.read(cloud_file_path) rescue nil
        @cloud_type
      end

    end # Platform

  end # RightScale

  # Initialize for current platform and/or force singleton creation on current
  # thread to avoid any weird threaded initialization issues.
  ::RightScale::Platform.instance

end # unless already defined
