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

require 'rubygems'
require 'fileutils'
require 'tmpdir'
require 'rbconfig'

begin
  require 'win32/dir'
  require 'windows/api'
  require 'windows/error'
  require 'windows/handle'
  require 'windows/security'
  require 'windows/system_info'
  require 'Win32API'
rescue LoadError => e
  raise e if !!(RbConfig::CONFIG['host_os'] =~ /mswin|win32|dos|mingw|cygwin/i)
end

module RightScale
  # Throw when a Win32 API fails.  Message will contain the last error message
  class Win32Error < Exception
    include ::Windows::Error

    def initialize(msg = "")
      super(msg)
      @last_error = get_last_error
    end

    def message
      original_message = super
      result = ""
      result << "#{original_message}\n  Error Detail: " unless original_message.nil? || original_message.empty?
      result << "#{@last_error}"
    end
  end

  # Windows specific implementation
  class Platform

    attr_reader :flavor, :release

    def init
      getversionex = Win32API.new("kernel32", "GetVersionEx", 'P', 'L')
      osversioninfo = [
        148,       # size of this struct (IN)
        0,         # major version (OUT)
        0,         # minor version (OUT)
        0,         # build (OUT)
        0,         # platform (OUT)
        "\0" * 128 # additional info (OUT)
      ].pack('LLLLLa128')

      raise 'Failed to detect Windows version' if 0 == getversionex.call(osversioninfo)  # zero is failure
      version = osversioninfo.unpack('LLLLLZ128') # 'Z' means ASCIIZ string
      @flavor = 'windows'  # there can be only one
      @release = "#{version[1]}.#{version[2]}.#{version[3]}"
    end

    class Filesystem
      MAX_PATH = 260

      @@get_temp_dir_api = nil

      def initialize
        @temp_dir = nil
      end

      # Is given command available in the PATH?
      #
      # === Parameters
      # command_name(String):: Name of command to be tested with
      # or without the expected windows file extension.
      #
      # === Return
      # true:: If command is in path
      # false:: Otherwise
      def has_executable_in_path(command_name)
        return nil != find_executable_in_path(command_name)
      end

      # Finds the given command name in the PATH. this emulates the 'which'
      # command from linux (without the terminating newline).
      #
      # === Parameters
      # command_name(String):: Name of command to be tested with
      # or without the expected windows file extension.
      #
      # === Return
      # path to first matching executable file in PATH or nil
      def find_executable_in_path(command_name)
        # must search all known (executable) path extensions unless the
        # explicit extension was given. this handles a case such as 'curl'
        # which can either be on the path as 'curl.exe' or as a command shell
        # shortcut called 'curl.cmd', etc.
        use_path_extensions = 0 == File.extname(command_name).length
        path_extensions = use_path_extensions ? ENV['PATHEXT'].split(/;/) : nil

        # must check the current working directory first just to be completely
        # sure what would happen if the command were executed. note that linux
        # ignores the CWD, so this is platform-specific behavior for windows.
        cwd = Dir.getwd
        path = ENV['PATH']
        path = (path.nil? || 0 == path.length) ? cwd : (cwd + ';' + path)
        path.split(/;/).each do |dir|
          if use_path_extensions
            path_extensions.each do |path_extension|
              path = File.join(dir, command_name + path_extension)
              return path if File.executable?(path)
            end
          else
            path = File.join(dir, command_name)
            return path if File.executable?(path)
          end
        end
        return nil
      end

      # Directory containing generated agent configuration files
      # @deprecated
      def cfg_dir
        warn "cfg_dir is deprecated; please use right_agent_cfg_dir"
        right_agent_cfg_dir
      end

      # RightScale state directory for the current platform
      # @deprecated
      def right_scale_state_dir
        warn "right_scale_state_dir is deprecated; please use either right_scale_static_state_dir or right_agent_dynamic_state_dir"
        right_scale_static_state_dir
      end

      # Directory containing generated agent configuration files
      def right_agent_cfg_dir
        return pretty_path(File.join(Dir::COMMON_APPDATA, 'RightScale', 'right_agent'))
      end

      # Static (time-invariant) state that is common to all RightScale apps/agents
      def right_scale_static_state_dir
        return pretty_path(File.join(Dir::COMMON_APPDATA, 'RightScale', 'rightscale.d'))
      end

      # Static (time-invariant) state that is specific to RightLink
      def right_link_static_state_dir
        return pretty_path(File.join(Dir::COMMON_APPDATA, 'RightScale', 'rightscale.d', 'right_link'))
      end

      # Dynamic, persistent runtime state that is specific to RightLink
      def right_link_dynamic_state_dir
        return pretty_path(File.join(Dir::COMMON_APPDATA, 'RightScale', 'right_link'))
      end

      # Spool directory for the current platform
      def spool_dir
        return pretty_path(File.join(Dir::COMMON_APPDATA, 'RightScale', 'spool'))
      end

      # Cache directory for the current platform
      def cache_dir
        return pretty_path(File.join(Dir::COMMON_APPDATA, 'RightScale', 'cache'))
      end

      # Log directory for the current platform
      def log_dir
        return pretty_path(File.join(Dir::COMMON_APPDATA, 'RightScale', 'log'))
      end

      # Source code, for reference purposes and for development.
      def source_code_dir
        return pretty_path(File.join(Dir::COMMON_APPDATA, 'RightScale', 'src'))
      end

      # Temp directory for the current platform
      def temp_dir
        if @temp_dir.nil?
          @@get_temp_dir_api = Win32::API.new('GetTempPath', 'LP', 'L') unless @@get_temp_dir_api
          buffer = 0.chr * MAX_PATH
          @@get_temp_dir_api.call(buffer.length, buffer)
          @temp_dir = pretty_path(buffer.unpack('A*').first.chomp('\\'))
        end
      rescue
        @temp_dir = File.join(Dir::WINDOWS, "temp")
      ensure
        return @temp_dir
      end

      # Path to place pid files
      def pid_dir
        return pretty_path(File.join(Dir::COMMON_APPDATA, 'RightScale', 'run'))
      end

      def right_link_home_dir
        unless @right_link_home_dir
          @right_link_home_dir = ENV['RS_RIGHT_LINK_HOME'] ||
                                 File.normalize_path(File.join(company_program_files_dir, 'RightLink'))
        end
        @right_link_home_dir
      end

      # Path to right link configuration and internal usage scripts
      def private_bin_dir
        return pretty_path(File.join(right_link_home_dir, 'bin'))
      end

      def sandbox_dir
        return pretty_path(File.join(right_link_home_dir, 'sandbox'))
      end

      # System root path
      def system_root
        return pretty_path(ENV['SystemRoot'])
      end

      # converts a long path to a short path. in windows terms, this means
      # taking any file/folder name over 8 characters in length and truncating
      # it to 6 characters with ~1..~n appended depending on how many similar
      # names exist in the same directory. file extensions are simply chopped
      # at three letters. the short name is equivalent for all API calls to
      # the long path but requires no special quoting, etc. the path must
      # exist at least partially for the API call to succeed.
      #
      # === Parameters
      # long_path(String):: fully or partially existing long path to be
      # converted to its short path equivalent.
      #
      # === Return
      # short_path(String):: short path equivalent or same path if non-existent
      def long_path_to_short_path(long_path)
        return File.long_path_to_short_path(long_path)
      end

      # specific to the windows environment to aid in resolving paths to
      # executables in test scenarios.
      def company_program_files_dir
        return pretty_path(File.join(Dir::PROGRAM_FILES, 'RightScale'))
      end

      # pretties up paths which assists Dir.glob() and Dir[] calls which will
      # return empty if the path contains any \ characters. windows doesn't
      # care (most of the time) about whether you use \ or / in paths. as
      # always, there are exceptions to this rule (such as "del c:/xyz" which
      # fails while "del c:\xyz" succeeds)
      #
      # === Parameters
      # path(String):: path to make pretty
      # native_fs_flag(Boolean):: true if path is pretty for native file
      #   system (i.e. file system calls more likely to succeed), false if
      #   pretty for Ruby interpreter (default).
      def pretty_path(path, native_fs_flag = false)
        return native_fs_flag ? path.gsub("/", "\\") : path.gsub("\\", "/")
      end

      # Ensures a local drive location for the file or folder given by path
      # by copying to a local temp directory given by name only if the item
      # does not appear on the home drive. This method is useful because
      # secure applications refuse to run scripts from network locations, etc.
      # Replaces any similar files in temp dir to ensure latest updates.
      #
      # === Parameters
      # path(String):: path to file or directory to be placed locally.
      #
      # temp_dir_name(String):: name (or relative path) of temp directory to
      # use only if the file or folder is not on a local drive.
      #
      # === Returns
      # result(String):: local drive path
      def ensure_local_drive_path(path, temp_dir_name)
        homedrive = ENV['HOMEDRIVE']
        if homedrive && homedrive.upcase != path[0,2].upcase
          local_dir = ::File.join(temp_dir, temp_dir_name)
          FileUtils.mkdir_p(local_dir)
          local_path = ::File.join(local_dir, ::File.basename(path))
          if ::File.directory?(path)
            FileUtils.rm_rf(local_path) if ::File.directory?(local_path)
            FileUtils.cp_r(::File.join(path, '.'), local_path)
          else
            FileUtils.cp(path, local_path)
          end
          path = local_path
        end
        return path
      end

      # Ruby 1.8.7 on Windows does not support File.symlink.  Windows Vista and newer
      # versions of Windows do support symlinks via CreateSymbolicLink, so we will use CreateSymbolicLink if it
      # is available, otherwise throw (on 2003 and earlier)
      #
      # === Parameters
      # old_name (String):: the path to the real file/directory
      # new_name (String):: the path to the link
      #
      # === Results
      # always 0 as does File.symlink
      #
      # === Raises
      # Win32Error:: if failed to create the link
      # PlatformNotSupported:: if the current platform does not support the CreateSymbolicLink API
      def create_symlink(old_name, new_name)
        raise ::RightScale::PlatformNotSupported, "Cannot create symlinks on this platform" unless defined?(::Windows::File::CreateSymbolicLink)
        flags = File.directory?(old_name) ? ::Windows::File::SYMBOLIC_LINK_FLAG_DIRECTORY : 0
        result = ::Windows::File::CreateSymbolicLink.call(new_name, old_name, flags)
        raise ::RightScale::Win32Error, "failed to create link from #{old_name} to #{new_name}"  unless (result == 1)
        0
      end
    end # Filesystem

    # Provides utilities for managing volumes (disks).
    class VolumeManager

      class ParserError < Exception; end
      class VolumeError < Exception; end

      def initialize
        @os_info = OSInformation.new

        @assignable_disk_regex = /^[D-Zd-z]:[\/\\]?$/
        @assignable_path_regex = /^[A-Za-z]:[\/\\][\/\\\w\s\d\-_\.~]+$/
      end

      # Determines if the given path is valid for a Windows volume attachemnt
      # (excluding the reserved A: B: C: drives).
      #
      # === Return
      # result(Boolean):: true if path is a valid volume root
      def is_attachable_volume_path?(path)
         return (nil != (path =~ @assignable_disk_regex) || nil != (path =~ @assignable_path_regex))
      end

      # Gets a list of physical or virtual disks in the form:
      #   [{:index, :status, :total_size, :free_size, :dynamic, :gpt}*]
      #
      # where
      #   :index >= 0
      #   :status = 'Online' | 'Offline'
      #   :total_size = bytes used by partitions
      #   :free_size = bytes not used by partitions
      #   :dynamic = true | false
      #   :gpt = true | false
      #
      # GPT = GUID partition table
      #
      # === Parameters
      # conditions{Hash):: hash of conditions to match or nil (default)
      #
      # === Return
      # volumes(Array):: array of hashes detailing visible volumes.
      #
      # === Raise
      # VolumeError:: on failure to list disks
      # ParserError:: on failure to parse disks from output
      def disks(conditions = nil)
        script = <<EOF
rescan
list disk
EOF
        exit_code, output_text = run_script(script)
        raise VolumeError.new("Failed to list disks: exit code = #{exit_code}\n#{script}\n#{output_text}") if exit_code != 0
        return parse_disks(output_text, conditions)
      end

      # Gets a list of currently visible volumes in the form:
      #   [{:index, :device, :label, :filesystem, :type, :total_size, :status, :info}*]
      #
      # where
      #   :index >= 0
      #   :device = "[A-Z]:"
      #   :label = up to 11 characters
      #   :filesystem = nil | 'NTFS' | <undocumented>
      #   :type = 'NTFS' | <undocumented>
      #   :total_size = size in bytes
      #   :status = 'Healthy' | <undocumented>
      #   :info = 'System' | empty | <undocumented>
      #
      # note that a strange aspect of diskpart is that it won't correlate
      # disks to volumes in any list even though partition lists are always
      # in the context of a selected disk.
      #
      # volume order can change as volumes are created/destroyed between
      # diskpart sessions so volume 0 can represent C: in one session and
      # then be represented as volume 1 in the next call to diskpart.
      #
      # volume labels are truncated to 11 characters by diskpart even though
      # NTFS allows up to 32 characters.
      #
      # === Parameters
      # conditions{Hash):: hash of conditions to match or nil (default)
      #
      # === Return
      # volumes(Array):: array of hashes detailing visible volumes.
      #
      # === Raise
      # VolumeError:: on failure to list volumes
      # ParserError:: on failure to parse volumes from output
      def volumes(conditions = nil)
        script = <<EOF
rescan
list volume
EOF
        exit_code, output_text = run_script(script)
        raise VolumeError.new("Failed to list volumes exit code = #{exit_code}\n#{script}\n#{output_text}") if exit_code != 0
        return parse_volumes(output_text, conditions)
      end

      # Gets a list of partitions for the disk given by index in the form:
      #   {:index, :type, :size, :offset}
      #
      # where
      #   :index >= 0
      #   :type = 'OEM' | 'Primary' | <undocumented>
      #   :size = size in bytes used by partition on disk
      #   :offset = offset of partition in bytes from head of disk
      #
      # === Parameters
      # disk_index(int):: disk index to query
      # conditions{Hash):: hash of conditions to match or nil (default)
      #
      # === Return
      # result(Array):: list of partitions or empty
      #
      # === Raise
      # VolumeError:: on failure to list partitions
      # ParserError:: on failure to parse partitions from output
      def partitions(disk_index, conditions = nil)
         script = <<EOF
rescan
select disk #{disk_index}
list partition
EOF
        exit_code, output_text = run_script(script)
        raise VolumeError.new("Failed to list partitions exit code = #{exit_code}\n#{script}\n#{output_text}") if exit_code != 0
        return parse_partitions(output_text, conditions)
      end

      # Formats a disk given by disk index and the device (e.g. "D:") for the
      # volume on the primary NTFS partition which will be created.
      #
      # === Parameters
      # disk_index(int): zero-based disk index (from disks list, etc.)
      # device(String):: disk letter or mount path specified for the volume to create
      #
      # === Return
      # always true
      #
      # === Raise
      # ArgumentError:: on invalid parameters
      # VolumeError:: on failure to format
      def format_disk(disk_index, device)
        if device.match(@assignable_path_regex) && @os_info.major < 6
          raise ArgumentError.new("Mount path assignment is not supported in this version of windows")
        end
        # note that creating the primary partition automatically creates and
        # selects a new volume, which can be assigned a letter before the
        # partition has actually been formatted.
        raise ArgumentError.new("Invalid index = #{disk_index}") unless disk_index >= 0
        raise ArgumentError.new("Invalid device = #{device}") unless is_attachable_volume_path?(device)

        # note that Windows 2003 server version of diskpart doesn't support
        # format so that has to be done separately.
        format_command = if @os_info.major < 6; ""; else; "format FS=NTFS quick"; end
        script = <<EOF
rescan
list disk
select disk #{disk_index}
#{get_clear_readonly_command('disk')}
#{get_online_disk_command}
clean
create partition primary
#{get_assign_command_for_device(device)}
#{format_command}
EOF
        exit_code, output_text = run_script(script)
        raise VolumeError.new("Failed to format disk #{disk_index} for device #{device}: exit code = #{exit_code}\n#{script}\n#{output_text}") if exit_code != 0

        # must format using command shell's FORMAT command before 2008 server.
        if @os_info.major < 6
          command = "echo Y | format #{device[0,1]}: /Q /V: /FS:NTFS"
          output_text = `#{command}`
          exit_code = $?.exitstatus
          raise VolumeError.new("Failed to format disk #{disk_index} for device #{device}: exit code = #{exit_code}\n#{output_text}") if exit_code != 0
        end
        true
      end

      # Brings the disk given by index online and clears the readonly
      # attribute, if necessary. The latter is required for some kinds of
      # disks to online successfully and SAN volumes may be readonly when
      # initially attached. As this change may bring additional volumes online
      # the updated volumes list is returned.
      #
      # === Parameters
      # disk_index(int):: zero-based disk index
      # options(Hash):: A hash of options which allows different behavior while onlining a drive.  Possible options are;
      #   :idempotent(Bool) - Checks the current disk statuses before attempting to online the disk.  If the drive is already online, it bails out making this method idempotent.
      #
      # === Return
      # always true
      #
      # === Raise
      # ArgumentError:: on invalid parameters
      # VolumeError:: on failure to online disk
      # ParserError:: on failure to parse volume list
      def online_disk(disk_index, options={})
        raise ArgumentError.new("Invalid disk_index = #{disk_index}") unless disk_index >= 0
        # Set some defaults for backward compatibility, allow user specified options to override defaults
        options = {:idempotent => false}.merge(options)
        script = <<EOF
rescan
list disk
select disk #{disk_index}
#{get_clear_readonly_command('disk')}
#{get_online_disk_command}
EOF

        if(options[:idempotent])
          disk = disks(:index => disk_index)
          return true if disk && disk[:status] == "Online"
        end

        exit_code, output_text = run_script(script)
        raise VolumeError.new("Failed to online disk #{disk_index}: exit code = #{exit_code}\n#{script}\n#{output_text}") if exit_code != 0
        true
      end

      # Brings the disk given by index offline
      #
      # === Parameters
      # disk_index(int):: zero-based disk index
      #
      # === Return
      # always true
      #
      # === Raise
      # ArgumentError:: on invalid parameters
      # VolumeError:: on failure to online disk
      # ParserError:: on failure to parse volume list
      def offline_disk(disk_index)
        raise ArgumentError.new("Invalid disk_index = #{disk_index}") unless disk_index >= 0
        # Set some defaults for backward compatibility, allow user specified options to override defaults
        script = <<EOF
rescan
list disk
select disk #{disk_index}
offline disk noerr
EOF

        exit_code, output_text = run_script(script)
        raise VolumeError.new("Failed to offline disk #{disk_index}: exit code = #{exit_code}\n#{script}\n#{output_text}") if exit_code != 0
        true
      end

      # Assigns the given device name to the volume given by index and clears
      # the readonly attribute, if necessary. The device must not currently be
      # in use.
      #
      # === Parameters
      # volume_device_or_index(int):: old device or zero-based volume index (from volumes list, etc.) to select for assignment.
      # device(String):: disk letter or mount path specified for the volume to create
      # options(Hash):: A hash of options which allows different behavior while assigning a device.  Possible options are:
      #   :clear_readonly(Bool) - Set to true by default, since the previous implementation of this method always cleared readonly
      #   :remove_all(Bool) - Removes all previously assigned devices and paths, essentially a big RESET button for volume assignment
      #   :idempotent(Bool) - Checks the current device assignments before assigning the device according to the specified parameters.  If the device is already assigned, it bails out making this method idempotent.
      #
      # === Return
      # always true
      #
      # === Raise
      # ArgumentError:: on invalid parameters
      # VolumeError:: on failure to assign device name
      # ParserError:: on failure to parse volume list
      def assign_device(volume_device_or_index, device, options={})
        # Set some defaults for backward compatibility, allow user specified options to override defaults
        options = {:clear_readonly => true, :idempotent => false}.merge(options)

        if device.match(@assignable_path_regex) && @os_info.major < 6
          raise ArgumentError.new("Mount path assignment is not supported in this version of windows")
        end
        # Volume selector for drive letter assignments
        volume_selector_match = volume_device_or_index.to_s.match(/^([D-Zd-z]|\d+):?$/)
        # Volume selector for mount path assignments
        volume_selector_match = volume_device_or_index.to_s.match(@assignable_path_regex) unless volume_selector_match
        raise ArgumentError.new("Invalid volume_device_or_index = #{volume_device_or_index}") unless volume_selector_match
        volume_selector = volume_selector_match[1]
        raise ArgumentError.new("Invalid device = #{device}") unless is_attachable_volume_path?(device)
        if(options[:idempotent])
          # Device already assigned?
          vols = volumes
          already_assigned = vols.select do |k,v|
              # The volume is specified by it's index and is already mounted to the specified device/path
              (k == :index && v == volume_device_or_index && vols[:device] == device) ||
              # The volume is specified by it's current device/path assignment and is already mounted to the specified device/path
              (k == :device && v == volume_device_or_index)
          end

          return true if already_assigned.length > 0
        end
        # Validation ends here, and real stuff starts to happen

        script = <<EOF
rescan
list volume
select volume "#{volume_selector}"
#{get_clear_readonly_command('volume') if options[:clear_readonly]}
#{"remove all noerr" if options[:remove_all]}
#{get_assign_command_for_device(device)}
EOF

        exit_code, output_text = run_script(script)
        raise VolumeError.new("Failed to assign device \"#{device}\" for volume \"#{volume_device_or_index}\": exit code = #{exit_code}\n#{script}\n#{output_text}") if exit_code != 0
        true
      end

      protected

      # Parses raw output from diskpart looking for the (first) disk list.
      #
      # Example of raw output from diskpart (column width is dictated by the
      # header and some columns can be empty):
      #
      #  Disk ###  Status      Size     Free     Dyn  Gpt
      #  --------  ----------  -------  -------  ---  ---
      #  Disk 0    Online        80 GB      0 B
      #* Disk 1    Offline     4096 MB  4096 MB
      #  Disk 2    Online      4096 MB  4096 MB   *
      #
      # === Parameters
      # output_text(String):: raw output from diskpart
      # conditions{Hash):: hash of conditions to match or nil (default)
      #
      # === Return
      # result(Array):: volumes or empty
      #
      # === Raise
      # ParserError:: on failure to parse disk list
      def parse_disks(output_text, conditions = nil)
        result = []
        line_regex = nil
        header_regex = /  --------  (-+)  -------  -------  ---  ---/
        header_match = nil
        output_text.each do |line|
          line = line.chomp
          if line_regex
            if line.strip.empty?
              break
            end
            match_data = line.match(line_regex)
            raise ParserError.new("Failed to parse disk info from #{line.inspect} using #{line_regex.inspect}") unless match_data
            data = {:index => match_data[1].to_i,
                    :status => match_data[2].strip,
                    :total_size => size_factor_to_bytes(match_data[3], match_data[4]),
                    :free_size => size_factor_to_bytes(match_data[5], match_data[6]),
                    :dynamic => match_data[7].strip[0,1] == '*',
                    :gpt => match_data[8].strip[0,1] == '*'}
            if conditions
              matched = true
              conditions.each do |key, value|
                unless data[key] == value
                  matched = false
                  break
                end
              end
              result << data if matched
            else
              result << data
            end
          elsif header_match = line.match(header_regex)
            # account for some fields being variable width between versions of the OS.
            status_width = header_match[1].length
            line_regex_text = "^[\\* ] Disk (\\d[\\d ]\{2\})  (.\{#{status_width}\})  "\
                              "[ ]?([\\d ]\{3\}\\d) (.?B)  [ ]?([\\d ]\{3\}\\d) (.?B)   ([\\* ])    ([\\* ])"
            line_regex = Regexp.compile(line_regex_text)
          else
            # one or more lines of ignored headers
          end
        end
        raise ParserError.new("Failed to parse disk list header from output #{output_text.inspect} using #{header_regex.inspect}") unless header_match
        return result
      end

      # Parses raw output from diskpart looking for the (first) volume list.
      #
      # Example of raw output from diskpart (column width is dictated by the
      # header and some columns can be empty):
      #
      #  Volume ###  Ltr  Label        Fs     Type        Size     Status     Info
      #  ----------  ---  -----------  -----  ----------  -------  ---------  --------
      #  Volume 0     C   2008Boot     NTFS   Partition     80 GB  Healthy    System
      #* Volume 1     D                NTFS   Partition   4094 MB  Healthy
      #  Volume 2                      NTFS   Partition   4094 MB  Healthy
      #
      # === Parameters
      # output_text(String):: raw output from diskpart
      # conditions{Hash):: hash of conditions to match or nil (default)
      #
      # === Return
      # result(Array):: volumes or empty.  Drive letters are appended with ':' even though they aren't
      # returned that way from diskpart
      #
      # === Raise
      # ParserError:: on failure to parse volume list
      def parse_volumes(output_text, conditions = nil)
        result = []
        header_regex = /  ----------  ---  (-+)  (-+)  (-+)  -------  (-+)  (-+)/
        header_match = nil
        line_regex = nil
        output_text.each do |line|
          line = line.chomp
          if line_regex
            if line.strip.empty?
              break
            end
            match_data = line.match(line_regex)
            unless match_data
              path_match_regex = /([A-Za-z]:[\/\\][\/\\\w\s\d]+)/
              match_data = line.match(path_match_regex)
              if match_data
                result.last[:device] = match_data[1]
                next
              end
            end
            raise ParserError.new("Failed to parse volume info from #{line.inspect} using #{line_regex.inspect}") unless match_data
            letter = nil_if_empty(match_data[2])
            device = "#{letter.upcase}:" if letter
            data = {:index => match_data[1].to_i,
                    :device => device,
                    :label => nil_if_empty(match_data[3]),
                    :filesystem => nil_if_empty(match_data[4]),
                    :type => nil_if_empty(match_data[5]),
                    :total_size => size_factor_to_bytes(match_data[6], match_data[7]),
                    :status => nil_if_empty(match_data[8]),
                    :info => nil_if_empty(match_data[9])}
            if conditions
              matched = true
              conditions.each do |key, value|
                unless data[key] == value
                  matched = false
                  break
                end
              end
              result << data if matched
            else
              result << data
            end
          elsif header_match = line.match(header_regex)
            # account for some fields being variable width between versions of the OS.
            label_width = header_match[1].length
            filesystem_width = header_match[2].length
            type_width = header_match[3].length
            status_width = header_match[4].length
            info_width = header_match[5].length
            line_regex_text = "^[\\* ] Volume (\\d[\\d ]\{2\})   ([A-Za-z ])   "\
                              "(.\{#{label_width}\})  (.\{#{filesystem_width}\})  "\
                              "(.\{#{type_width}\})  [ ]?([\\d ]\{3\}\\d) (.?B)\\s{0,2}"\
                              "(.\{#{status_width}\})\\s{0,2}(.\{0,#{info_width}\})"
            line_regex = Regexp.compile(line_regex_text)
          else
            # one or more lines of ignored headers
          end
        end
        raise ParserError.new("Failed to parse volume list header from output #{output_text.inspect} using #{header_regex.inspect}") unless header_match
        return result
      end

      # Parses raw output from diskpart looking for the (first) partition list.
      #
      # Example of raw output from diskpart (column width is dictated by the
      # header and some columns can be empty):
      #
      #  Partition ###  Type              Size     Offset
      #  -------------  ----------------  -------  -------
      #  Partition 1    OEM                 39 MB    31 KB
      #* Partition 2    Primary             14 GB    40 MB
      #  Partition 3    Primary            451 GB    14 GB
      #
      # === Parameters
      # output_text(String):: raw output from diskpart
      # conditions{Hash):: hash of conditions to match or nil (default)
      #
      # === Return
      # result(Array):: volumes or empty
      #
      # === Raise
      # ParserError:: on failure to parse volume list
      def parse_partitions(output_text, conditions = nil)
        result = []
        header_regex = /  -------------  (-+)  -------  -------/
        header_match = nil
        line_regex = nil
        output_text.each do |line|
          line = line.chomp
          if line_regex
            if line.strip.empty?
              break
            end
            match_data = line.match(line_regex)
            raise ParserError.new("Failed to parse partition info from #{line.inspect} using #{line_regex.inspect}") unless match_data
            data = {:index => match_data[1].to_i,
                    :type => nil_if_empty(match_data[2]),
                    :size => size_factor_to_bytes(match_data[3], match_data[4]),
                    :offset => size_factor_to_bytes(match_data[5], match_data[6])}
            if conditions
              matched = true
              conditions.each do |key, value|
                unless data[key] == value
                  matched = false
                  break
                end
              end
              result << data if matched
            else
              result << data
            end
          elsif header_match = line.match(header_regex)
            # account for some fields being variable width between versions of the OS.
            type_width = header_match[1].length
            line_regex_text = "^[\\* ] Partition (\\d[\\d ]\{2\})  (.\{#{type_width}\})  "\
                              "[ ]?([\\d ]\{3\}\\d) (.?B)  [ ]?([\\d ]\{3\}\\d) (.?B)"
            line_regex = Regexp.compile(line_regex_text)
          elsif line.start_with?("There are no partitions on this disk")
            return []
          else
            # one or more lines of ignored headers
          end
        end
        raise ParserError.new("Failed to parse volume list header from output #{output_text.inspect} using #{header_regex.inspect}") unless header_match
        return result
      end

      # Run a diskpart script and get the exit code and text output. See also
      # technet and search for "DiskPart Command-Line Options" or else
      # "http://technet.microsoft.com/en-us/library/cc766465%28WS.10%29.aspx".
      # Note that there are differences between 2003 and 2008 server versions
      # of this utility.
      #
      # === Parameters
      # script(String):: diskpart script with commands delimited by newlines
      #
      # === Return
      # result(Array):: tuple of [exit_code, output_text]
      def run_script(script)
        Dir.mktmpdir do |temp_dir_path|
          script_file_path = File.join(temp_dir_path, "rs_diskpart_script.txt")
          File.open(script_file_path, "w") { |f| f.puts(script.strip) }
          executable_path = "diskpart.exe"
          executable_arguments = ["/s", File.normalize_path(script_file_path)]
          shell = RightScale::Platform.shell
          executable_path, executable_arguments = shell.format_right_run_path(executable_path, executable_arguments)
          command = shell.format_executable_command(executable_path, executable_arguments)
          output_text = `#{command}`
          return $?.exitstatus, output_text
        end
      end

      # Determines if the given value is empty and returns nil in that case.
      #
      # === Parameters
      # value(String):: value to chec
      #
      # === Return
      # result(String):: trimmed value or nil
      def nil_if_empty(value)
        value = value.strip
        return nil if value.empty?
        return value
      end

      # Multiplies a raw size value by a size factor given as a standardized
      # bytes acronym.
      #
      # === Parameters
      # size_by(String or Number):: value to multiply
      # size_factor(String):: multiplier acronym
      #
      # === Return
      # result(int):: bytes
      def size_factor_to_bytes(size_by, size_factor)
        value = size_by.to_i
        case size_factor
        when 'KB' then return value * 1024
        when 'MB' then return value * 1024 * 1024
        when 'GB' then return value * 1024 * 1024 * 1024
        when 'TB' then return value * 1024 * 1024 * 1024 * 1024
        else return value # assume bytes
        end
      end

      # Returns the correct diskpart assignment command for the specified device (either drive letter, or path)
      #
      # === Parameters
      # device(String):: Either a drive letter or mount path
      #
      # === Return
      # result(String):: The correct diskpart assignment command
      def get_assign_command_for_device(device)
        if device.match(@assignable_disk_regex)
          "assign letter=#{device[0,1]}"
        elsif device.match(@assignable_path_regex)
          "assign mount=\"#{device}\""
        end
      end

      # Returns the correct 'online disk' diskpart command based on the OS version
      #
      # === Return
      # result(String):: Either "online noerr" or "online disk noerr" depending upon the OS version
      def get_online_disk_command()
        if @os_info.major < 6; "online noerr" else; "online disk noerr" end
      end

      # Returns the correct 'attribute disk clear readonly' diskpart command based on the OS version
      #
      # === Parameters
      # object_type(String):: One of "disk" or "volume" to clear read only for
      #
      # === Return
      # result(String):: Either a blank string or "attribute #{object_type} clear readonly noerr" depending upon the OS version
      def get_clear_readonly_command(object_type)
        if @os_info.major < 6; "" else; "attribute #{object_type} clear readonly noerr" end
      end

    end # VolumeManager

    # Provides utilities for formatting executable shell commands, etc.
    class Shell
      POWERSHELL_V1x0_EXECUTABLE_PATH = "powershell.exe"
      POWERSHELL_V1x0_SCRIPT_EXTENSION = ".ps1"
      RUBY_SCRIPT_EXTENSION = ".rb"
      NULL_OUTPUT_NAME = "nul"

      @@executable_extensions = nil
      @@right_run_path = nil

      # Formats an executable path and arguments by inserting a reference to
      # RightRun.exe on platforms only when necessary.
      #
      # === Parameters
      # executable_path(String):: 64-bit executable path
      # executable_arguments(Array):: arguments for 64-bit executable
      #
      # === Return
      # result(Array):: tuple for updated [executable_path, executable_arguments]
      def format_right_run_path(executable_path, executable_arguments)
        if @@right_run_path.nil?
          @@right_run_path = ""
          if ENV['ProgramW6432'] && (@@right_run_path = ENV['RS_RIGHT_RUN_EXE'].to_s).empty?
            temp_path = File.join(ENV['ProgramW6432'], 'RightScale', 'Shared', 'RightRun.exe')
            if File.file?(temp_path)
              @@right_run_path = File.normalize_path(temp_path).gsub("/", "\\")
            end
          end
        end
        unless @@right_run_path.empty?
          executable_arguments.unshift(executable_path)
          executable_path = @@right_run_path
        end

        return executable_path, executable_arguments
      end

      # Formats a script file name to ensure it is executable on the current
      # platform.
      #
      # === Parameters
      # partial_script_file_path(String):: full or partial script file path
      #
      # default_extension(String):: default script extension for platforms
      # which require a known file extension to execute.
      #
      # === Returns
      # executable_script_file_path(String):: executable path
      def format_script_file_name(partial_script_file_path, default_extension = POWERSHELL_V1x0_SCRIPT_EXTENSION)
        extension = File.extname(partial_script_file_path)
        if 0 == extension.length
          return partial_script_file_path + default_extension
        end

        # quick out for default extension.
        if 0 == (extension <=> default_extension)
          return partial_script_file_path
        end

        # confirm that the "extension" is really something understood by
        # the command shell as being executable.
        if @@executable_extensions.nil?
          @@executable_extensions = ENV['PATHEXT'].downcase.split(';')
        end
        if @@executable_extensions.include?(extension.downcase)
          return partial_script_file_path
        end

        # not executable; use default extension.
        return partial_script_file_path + default_extension
      end

      # Formats an executable command by quoting any of the arguments as
      # needed and building an executable command string.
      #
      # === Parameters
      # executable_file_path(String):: full or partial executable file path
      #
      # arguments(Array):: variable stringizable arguments
      #
      # === Returns
      # executable_command(String):: executable command string
      def format_executable_command(executable_file_path, *arguments)
        escaped = []
        [executable_file_path, arguments].flatten.each do |arg|
          value = arg.to_s
          escaped << (value.index(' ') ? "\"#{value}\"" : value)
        end

        # let cmd do the extension resolution if no extension was given
        ext = File.extname(executable_file_path)
        if ext.nil? || ext.empty?
          "cmd.exe /C \"#{escaped.join(" ")}\""
        else
          escaped.join(" ")
        end
      end

      # Formats a powershell command using the given script path and arguments.
      # Allows for specifying powershell from a specific installed location.
      # This method is only implemented for Windows.
      #
      # === Parameters
      # shell_script_file_path(String):: shell script file path
      # arguments(Array):: variable stringizable arguments
      #
      # === Returns
      # executable_command(string):: executable command string
      def format_powershell_command(shell_script_file_path, *arguments)
        return format_powershell_command4(POWERSHELL_V1x0_EXECUTABLE_PATH, nil, nil, shell_script_file_path, *arguments)
      end

      # Formats a ruby command using the given script path and arguments.
      # This method is only implemented for Windows since ruby scripts on
      # linux should rely on shebang to indicate the ruby bin path.
      #
      # === Parameters
      # shell_script_file_path(String):: shell script file path
      # arguments(Array):: variable stringizable arguments
      #
      # === Returns
      # executable_command(string):: executable command string
      def format_ruby_command(shell_script_file_path, *arguments)
        return format_executable_command(sandbox_ruby, *([shell_script_file_path] + arguments))
      end

      # Formats a powershell command using the given script path and arguments.
      # Allows for specifying powershell from a specific installed location.
      # This method is only implemented for Windows.
      #
      # === Parameters
      # powershell_exe_path(String):: path to powershell executable
      # shell_script_file_path(String):: shell script file path
      # arguments(Array):: variable stringizable arguments
      #
      # === Returns
      # executable_command(string):: executable command string
      def format_powershell_command4(powershell_exe_path,
                                     lines_before_script,
                                     lines_after_script,
                                     shell_script_file_path,
                                     *arguments)
        # special case for powershell scripts.
        escaped = []
        [shell_script_file_path, arguments].flatten.each do |arg|
          value = arg.to_s
          # note that literal ampersand must be quoted on the powershell command
          # line because it otherwise means 'execute what follows'.
          escaped << ((value.index(' ') || value.index('&')) ? "'#{value.gsub("'", "''")}'" : value)
        end

        # resolve lines before & after script.
        defaulted_lines_after_script = lines_after_script.nil?
        lines_before_script ||= []
        lines_after_script ||= []

        # execute powershell with RemoteSigned execution policy. the issue
        # is that powershell by default will only run digitally-signed
        # scripts.
        # FIX: search for any attempt to alter execution policy in lines
        # before insertion.
        # FIX: support digitally signed scripts and/or signing on the fly by
        # checking for a signature file side-by-side with script.
        lines_before_script.insert(0, "set-executionpolicy -executionPolicy RemoteSigned -Scope Process")

        # insert error checking only in case of defaulted "lines after script"
        # to be backward compatible with existing scripts.
        if defaulted_lines_after_script
          # ensure for a generic powershell script that any errors left in the
          # global $Error list are noted and result in script failure. the
          # best practice is for the script to handle errors itself (and clear
          # the $Error list if necessary), so this is a catch-all for any
          # script which does not handle errors "properly".
          lines_after_script << "if ($NULL -eq $LastExitCode) { $LastExitCode = 0 }"
          lines_after_script << "if ((0 -eq $LastExitCode) -and ($Error.Count -gt 0)) { $RS_message = 'Script exited successfully but $Error contained '+($Error.Count)+' error(s).'; Write-warning $RS_message; $LastExitCode = 1 }"
        end

        # ensure last exit code gets marshalled.
        marshall_last_exit_code_cmd = "exit $LastExitCode"
        if defaulted_lines_after_script || (lines_after_script.last != marshall_last_exit_code_cmd)
          lines_after_script << marshall_last_exit_code_cmd
        end

        # format powershell command string.
        powershell_command = "&{#{lines_before_script.join("; ")}; &#{escaped.join(" ")}; #{lines_after_script.join("; ")}}"

        # in order to run 64-bit powershell from this 32-bit ruby process, we need to launch it using
        # our special RightRun utility from program files, if it is installed (it is not installed for
        # 32-bit instances and perhaps not for test/dev environments).
        executable_path = powershell_exe_path
        executable_arguments = ["-command", powershell_command]
        executable_path, executable_arguments = format_right_run_path(executable_path, executable_arguments)

        # combine command string with powershell executable and arguments.
        return format_executable_command(executable_path, executable_arguments)
      end

      # Formats a shell command using the given script path and arguments.
      #
      # === Parameters
      # shell_script_file_path(String):: shell script file path
      # arguments(Array):: variable stringizable arguments
      #
      # === Returns
      # executable_command(string):: executable command string
      def format_shell_command(shell_script_file_path, *arguments)
        # special case for powershell scripts and ruby scripts (because we
        # don't necessarily setup the association for .rb with our sandbox
        # ruby in the environment).
        extension = File.extname(shell_script_file_path)
        unless extension.to_s.empty?
          if 0 == POWERSHELL_V1x0_SCRIPT_EXTENSION.casecmp(extension)
            return format_powershell_command(shell_script_file_path, *arguments)
          elsif 0 == RUBY_SCRIPT_EXTENSION.casecmp(extension)
            return format_ruby_command(shell_script_file_path, *arguments)
          end
        end

        # execution is based on script extension (.bat, .cmd, .js, .vbs, etc.)
        return format_executable_command(shell_script_file_path, *arguments)
      end

      # Formats a command string to redirect stdout to the given target.
      #
      # === Parameters
      # cmd(String):: executable command string
      #
      # target(String):: target file (optional, defaults to nul redirection)
      def format_redirect_stdout(cmd, target = NULL_OUTPUT_NAME)
        return cmd + " 1>#{target}"
      end

      # Formats a command string to redirect stderr to the given target.
      #
      # === Parameters
      # cmd(String):: executable command string
      #
      # target(String):: target file (optional, defaults to nul redirection)
      def format_redirect_stderr(cmd, target = NULL_OUTPUT_NAME)
        return cmd + " 2>#{target}"
      end

      # Formats a command string to redirect both stdout and stderr to the
      # given target.
      #
      # === Parameters
      # cmd(String):: executable command string
      #
      # target(String):: target file (optional, defaults to nul redirection)
      def format_redirect_both(cmd, target = NULL_OUTPUT_NAME)
        return cmd + " 1>#{target} 2>&1"
      end

      # Returns path to sandbox ruby executable.
      def sandbox_ruby
        unless @sandbox_ruby
          @sandbox_ruby = ENV['RS_RUBY_EXE'] ||
                          File.normalize_path(File.join(RightScale::Platform.filesystem.sandbox_dir, 'Ruby', 'bin', 'ruby.exe'))
        end
        @sandbox_ruby
      end

      # Gets the current system uptime.
      #
      # === Return
      # the time the machine has been up in seconds, 0 if there was an error.
      def uptime
        begin
          return Time.now.to_i.to_f - booted_at.to_f
        rescue Exception
          return 0.0
        end
      end

      # Gets the time at which the system was booted
      #
      # === Return
      # the UTC timestamp at which the system was booted
      def booted_at
        begin
          Dir.mktmpdir do |temp_dir_path|
            Dir.chdir(temp_dir_path) do
              wmic_output = `echo | wmic OS Get LastBootUpTime`
            end
          end

          match = /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.\d{6}([+-]\d{3})/.match(wmic_output)

          year, mon, day, hour, min, sec, tz = match[1..-1]

          #Convert timezone from [+-]mmm to [+-]hh:mm
          tz = "#{tz[0...1]}#{(tz.to_i.abs / 60).to_s.rjust(2,'0')}:#{(tz.to_i.abs % 60).to_s.rjust(2,'0')}"

          #Finally, parse the WMIC output as an XML-schema time, which is the only reliable
          #way to parse a time with arbitrary zone in Ruby (?!)
          return Time.xmlschema("#{year}-#{mon}-#{day}T#{hour}:#{min}:#{sec}#{tz}").to_i
        rescue Exception
          return nil
        end
      end

    end # Shell

    class Controller
      include ::Windows::Process
      include ::Windows::Error
      include ::Windows::Handle
      include ::Windows::Security

      @@initiate_system_shutdown_api = nil

      # Shutdown machine now
      def shutdown
        initiate_system_shutdown(false)
      end

      # Reboot machine now
      def reboot
        initiate_system_shutdown(true)
      end

      private

      def initiate_system_shutdown(reboot_after_shutdown)

        @@initiate_system_shutdown_api = Win32::API.new('InitiateSystemShutdown', 'PPLLL', 'B', 'advapi32') unless @@initiate_system_shutdown_api

        # get current process token.
        token_handle = 0.chr * 4
        unless OpenProcessToken(process_handle = GetCurrentProcess(),
                                desired_access = TOKEN_ADJUST_PRIVILEGES + TOKEN_QUERY,
                                token_handle)
           raise get_last_error
        end
        token_handle = token_handle.unpack('V')[0]

        begin
          # lookup shutdown privilege ID.
          luid = 0.chr * 8
          unless LookupPrivilegeValue(system_name = nil,
                                      priviledge_name = 'SeShutdownPrivilege',
                                      luid)
            raise get_last_error
          end
          luid = luid.unpack('VV')

          # adjust token privilege to enable shutdown.
          token_privileges       = 0.chr * 16                        # TOKEN_PRIVILEGES tokenPrivileges;
          token_privileges[0,4]  = [1].pack("V")                     # tokenPrivileges.PrivilegeCount = 1;
          token_privileges[4,8]  = luid.pack("VV")                   # tokenPrivileges.Privileges[0].Luid = luid;
          token_privileges[12,4] = [SE_PRIVILEGE_ENABLED].pack("V")  # tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
          unless AdjustTokenPrivileges(token_handle,
                                       disable_all_privileges = 0,
                                       token_privileges,
                                       new_state = 0,
                                       previous_state = nil,
                                       return_length = nil)
            raise get_last_error
          end
          unless @@initiate_system_shutdown_api.call(machine_name = nil,
                                                     message = nil,
                                                     timeout_secs = 1,
                                                     force_apps_closed = 1,
                                                     reboot_after_shutdown ? 1 : 0)
            raise get_last_error
          end
        ensure
          CloseHandle(token_handle)
        end
        true
      end

    end # Controller

    class Rng
      def pseudorandom_bytes(count)
        bytes = ''
        count.times do
          bytes << rand(0xff)
        end

        bytes
      end
    end

    class Process
      include ::Windows::Process

      @@get_process_memory_info = nil

      # see PROCESS_MEMORY_COUNTERS structure: "http://msdn.microsoft.com/en-us/library/ms684877%28VS.85%29.aspx"
      SIZEOF_PROCESS_MEMORY_COUNTERS = 10 * 4

      # queries resident set size (current working set size in Windows).
      #
      # === Parameters
      # pid(Fixnum):: process ID or nil for current process
      #
      # === Return
      # result(Fixnum):: current set size in KB
      def resident_set_size(pid=nil)
        @@get_process_memory_info = ::Win32::API.new("GetProcessMemoryInfo", 'LPL', 'B', 'psapi') unless @@get_process_memory_info

        # FIX: call OpenProcess and ensure proper access and close if given PID.
        raise NotImplementedError.new("pid != nil not yet implemented") if pid
        process_handle = GetCurrentProcess()
        process_memory_counters = "\0" * SIZEOF_PROCESS_MEMORY_COUNTERS
        result = @@get_process_memory_info.call(process_handle, process_memory_counters, process_memory_counters.size)
        # note that the 'B' return type is a Fixnum (i.e. not TrueClass or FalseClass) of 'zero' on failure or 'non-zero' on success
        raise ::RightScale::Win32Error.new("Failed to get resident set size for process") if 0 == result

        # current .WorkingSetSize (bytes) is equivalent of Linux' ps resident set size (KB)
        return process_memory_counters[12..16].unpack("L")[0] / 1024  # bytes to KB
      end
    end
    
    class Installer
      def install(packages)
        raise ::RightScale::Win32Error.new("Not implemented yet")
      end
    end

    # internal class for querying OS version, etc.
    class OSInformation
      include ::Windows::SystemInfo

      attr_reader :version, :major, :minor, :build

      def initialize
        @version = GetVersion()
        @major = LOBYTE(LOWORD(version))
        @minor = HIBYTE(LOWORD(version))
        @build = HIWORD(version)
      end
    end

  end # Platform

end # RightScale
