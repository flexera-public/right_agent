#
# Copyright (c) 2013 RightScale Inc
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

require ::File.expand_path('../../../platform', __FILE__)

module RightScale

  # Unix-specific implementation
  class Platform

    class Filesystem

      # Overrides base Filesystem#find_executable_in_path
      def find_executable_in_path(command_name)
        ::ENV['PATH'].split(/;|:/).each do |dir|
          path = ::File.join(dir, command_name)
          return path if ::File.executable?(path)
        end
        return nil
      end

      # Overrides base Filesystem#right_agent_cfg_dir
      def right_agent_cfg_dir
        '/var/lib/rightscale/right_agent'
      end

      # Overrides base Filesystem#right_scale_static_state_dir
      def right_scale_static_state_dir
        '/etc/rightscale.d'
      end

      # Overrides base Filesystem#right_link_static_state_dir
      def right_link_static_state_dir
        '/etc/rightscale.d/right_link'
      end

      # Overrides base Filesystem#right_link_dynamic_state_dir
      def right_link_dynamic_state_dir
        '/var/lib/rightscale/right_link'
      end

      # Overrides base Filesystem#spool_dir
      def spool_dir
        '/var/spool'
      end

      # Overrides base Filesystem#ssh_cfg_dir
      def ssh_cfg_dir
        '/etc/ssh'
      end

      # Overrides base Filesystem#cache_dir
      def cache_dir
        '/var/cache'
      end

      # Overrides base Filesystem#log_dir
      def log_dir
        '/var/log'
      end

      # Overrides base Filesystem#source_code_dir
      def source_code_dir
        '/usr/src'
      end

      # Overrides base Filesystem#temp_dir
      def temp_dir
        '/tmp'
      end

      # Overrides base Filesystem#pid_dir
      def pid_dir
        '/var/run'
      end

      # Overrides base Filesystem#right_link_home_dir
      def right_link_home_dir
        # TEAL FIX could the user choose a different directory when installing
        # the RightLink v5.9+ package manually?
        '/opt/rightscale'
      end

      # Overrides base Filesystem#private_bin_dir
      def private_bin_dir
        ::File.join(right_link_home_dir, 'bin')
      end

      # Overrides base Filesystem#sandbox_dir
      def sandbox_dir
        ::File.join(right_link_home_dir, 'sandbox')
      end

      # Overrides base Filesystem#long_path_to_short_path
      def long_path_to_short_path(long_path)
        return long_path
      end

      # Overrides base Filesystem#pretty_path
      def pretty_path(path, native_fs_flag = false)
        return path
      end

      # Overrides base Filesystem#ensure_local_drive_path
      def ensure_local_drive_path(path, temp_dir_name)
        return path
      end

      # Overrides base Filesystem#create_symlink
      def create_symlink(from_path, to_path)
        ::File.symlink(from_path, to_path)
      end
    end

    # Provides utilities for managing volumes (disks).
    class VolumeManager

      # Mounts a volume (returned by VolumeManager.volumes) to the mountpoint
      # specified.
      #
      # @param [Hash] volume info hash (as returned by VolumeManager.volumes)
      # @param [String] mountpoint where the device will be mounted in the file system
      #
      # @return [TrueClass] always true
      #
      # @raise [VolumeError] on a failure to mount the device
      def mount_volume(volume, mountpoint)
        must_be_overridden
      end
    end # VolumeManager

    class Shell
      # defined for backward compatibility; use Shell#null_output_name
      NULL_OUTPUT_NAME = '/dev/null'

      # Overrides base Shell#null_output_name
      def null_output_name
        NULL_OUTPUT_NAME
      end

      # Overrides base Shell#format_script_file_name
      def format_script_file_name(partial_script_file_path, default_extension = nil)
        # shell files containing shebang are directly executable in Unix, so
        # assume our scripts have shebang. if not, the error should be obvious.
        return partial_script_file_path
      end

      # Overrides base Shell#format_executable_command
      def format_executable_command(executable_file_path, *arguments)
        escaped = []
        space = ' '
        double_quote = '"'
        single_quote = "'"
        [executable_file_path, arguments].flatten.each do |arg|
          value = arg.to_s
          needs_escape =
            value.index(space) ||
            value.index(double_quote) ||
            value.index(single_quote)
          escaped << (needs_escape ? "\"#{value.gsub(double_quote, "\\\"")}\"" : value)
        end
        return escaped.join(space)
      end

      # Overrides base Shell#format_shell_command
      def format_shell_command(shell_script_file_path, *arguments)
        # shell files containing shebang are directly executable in Unix, so
        # assume our scripts have shebang. if not, the error should be obvious.
        return format_executable_command(shell_script_file_path, arguments)
      end

      # Overrides base Shell#sandbox_ruby
      def sandbox_ruby
        "#{::RightScale::Platform.filesystem.sandbox_dir}/bin/ruby"
      end
    end

    class Rng

      # Overrides base Rng#pseudorandom_bytes
      def pseudorandom_bytes(count)
        result = nil
        ::File.open('/dev/urandom', 'r') { |f| result = f.read(count) }
        result
      end
    end

    class Process

      # Overrides base Process#resident_set_size
      def resident_set_size(pid = nil)
        pid = $$ unless pid
        output_text = execute("ps -o rss= -p #{pid}")
        return output_text.to_i
      end
    end

    private

    # Overrides base Platform#initialize_genus
    def initialize_genus
      true # do nothing
    end

  end # Platform

end # RightScale
