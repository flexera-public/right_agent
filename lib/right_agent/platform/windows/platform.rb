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

require ::File.expand_path('../../../platform', __FILE__)

require 'fileutils'
require 'tmpdir'
begin
  # for shell folder definitions such as Dir::COMMON_APPDATA.
  # older versions use win32/api, latest uses ffi.
  require 'win32/dir'
rescue LoadError
  # ignore unless Windows as a concession to spec testing from non-Windows.
  # any windows-only gems must be fully mocked under test.
  raise if RUBY_PLATFORM =~ /mswin|mingw/
end

module RightScale

  # Windows specific implementation
  class Platform

    # exceptions
    class Win32Error < ::RightScale::Exceptions::PlatformError
      attr_reader :error_code

      # @param [String] context for message
      # @param [Integer] error_code for formatting or nil for last error
      def initialize(context, error_code = nil)
        @error_code = error_code || ::RightScale::Platform.windows_common.GetLastError()
        super(format_error_message(context, @error_code))
      end

      # Formats using system error message, if any.
      #
      # @param [String] context for message
      # @param [Integer] error_code for formatting
      #
      # @return [String] formatted error message
      def format_error_message(context, error_code)
        error_message = error_message_for(error_code)
        result = []
        result << context.to_s if context && !context.empty?
        result << "Win32 error code = #{error_code}"
        result << error_message if error_message && !error_message.empty?
        result.join("\n")
      end

      # Queries raw error message for given error code.
      #
      # @param [Integer] error_code for query
      #
      # @return [String] system error message or empty
      def error_message_for(error_code)
        # this API won't respond with required buffer size if buffer is too
        # small; it returns zero and there is no way to tell if there is no
        # valid message or the buffer is too small. use a 4KB buffer to avoid
        # failure due to buffer size.
        buffer = 0.chr * 4096
        flags = ::RightScale::Platform::WindowsCommon::FORMAT_MESSAGE_FROM_SYSTEM |
                ::RightScale::Platform::WindowsCommon::FORMAT_MESSAGE_IGNORE_INSERTS
        length = ::RightScale::Platform.windows_common.FormatMessage(
          flags, nil, error_code, 0, buffer, buffer.size, nil)
        buffer[0, length].strip
      end
    end

    # helpers
    class PlatformHelperBase

      # constants
      SIZEOF_DWORD = 4  # double-word
      SIZEOF_QWORD = 8  # quad-word or double-dword

      private

      # checks for mistakes in parameter passing even though neither ruby nor
      # Windows APIs are are strict about boolean types.
      def must_be_bool(value)
        value.is_a?(TrueClass) || value.is_a?(FalseClass) ||
          (raise ::ArgumentError, 'not a boolean')
      end

      # integer values are constrained to DWORDs for most Windows APIs. 64-bit
      # integers are passed as QWORD structures. negative values in native
      # languages have the high bit (0x80000000) set so no valid negative DWORD
      # can have the high bit set.
      def must_be_dword(value)
        (value.is_a?(Integer) && value >= -0x7fffffff && value <= 0xffffffff) ||
          (raise ::ArgumentError, 'not a dword')
      end

      # strings passed to Windows APIs must always be NUL-terminated because
      # Windows APIs will overrun buffers and fail without explanation.
      def must_be_string(value)
        (value.is_a?(String) && !value.empty? && value[-1].ord == 0) ||
          (raise ::ArgumentError, 'not a NUL-terminated string')
      end

      def must_be_string_or_nil(value, &callback)
        value.nil? || must_be_string(value, &callback)
      end

      # input buffers (structures) need only be a valid string buffer. some APIs
      # accept variable-sized structures that contain counts of substructures
      # instead of an overall size.
      def must_be_buffer(value)
        value.is_a?(String) || (raise ::ArgumentError, 'not a string buffer')
      end

      def must_be_buffer_or_nil(value)
        value.nil? || must_be_buffer(value)
      end

      # some Windows APIs count buffer size in bytes and the ruby buffer size
      # must agree with byte count.
      def must_be_byte_buffer(value, count)
        must_be_buffer(value)
        must_be_dword(count)
        count == value.bytesize || (raise ::ArgumentError, 'unexpected byte count')
      end

      def must_be_byte_buffer_or_nil(value, count)
        if value.nil?
          count == 0 || (raise ::ArgumentError, 'nil buffer must have a zero byte count')
        else
          must_be_byte_buffer(value, count)
        end
      end

      # some Windows APIs count buffer size in characters and the ruby buffer
      # length must agree with character count.
      def must_be_char_buffer(value, count)
        must_be_buffer(value)
        must_be_dword(count)
        count == value.size || (raise ::ArgumentError, 'unexpected character count')
      end

      def must_be_char_buffer_or_nil(value, count)
        if value.nil?
          count == 0 || (raise ::ArgumentError, 'nil buffer must have a zero character count')
        else
          must_be_char_buffer(value, count)
        end
      end

      # some Windows APIs accept a struct that contains a leading DWORD with the
      # size in bytes of the entire struct. even stranger, some have both a
      # leading DWORD and an additional argument that both specify struct size.
      def must_be_size_prefixed_buffer(value, count = nil)
        must_be_buffer(value)
        (value.bytesize >= SIZEOF_DWORD) ||
          (raise ::ArgumentError, 'insufficient buffer size')
        (value[0, SIZEOF_DWORD].unpack('L')[0] == value.bytesize) ||
          (raise ::ArgumentError, 'unexpected buffer size')
        count.nil? || count == value.size || (raise ::ArgumentError, 'unexpected buffer size')
      end

      def must_be_size_prefixed_buffer_or_nil(value, count = nil)
        if value.nil?
          count.nil? || count == 0 || (raise ::ArgumentError, 'nil buffer must have a zero character count')
        else
          must_be_size_prefixed_buffer(value, count)
        end
      end

      # Many Windows APIs follow a pattern of taking a buffer and buffer size as
      # arguments and returning the required buffer size if the buffer is too
      # small or else the exact length of the data if the buffer was sufficient.
      # This method implements retry loop logic for such APIs. The details of
      # how the API is called is left to the block after the buffer has been
      # created.
      #
      # @param [Integer] initial_buffer_count or zero to query required buffer
      #  size (Default = MAX_PATH).
      # @param [Integer] max_tries to raise out of loop in case the API
      #  will not settle on a buffer size (Default = 4).
      # @param [Integer] max_buffer_size to raise out of loop in case the API
      #  demands an unreasonable buffer size (Default = 64KB).
      #
      # @yield [buffer] yields the buffer at current size for API call
      # @yieldparam [String] buffer to use for API call (get size from buffer)
      #  or else nil if the last call returned zero (usually an API error).
      #
      # @return [String] buffered data clipped to exact length
      def with_resizable_buffer(initial_buffer_count = Filesystem::MAX_PATH,
                                max_tries = 4,
                                max_buffer_size = 0x10000)
        try_count = 0
        buffer_count = initial_buffer_count
        buffer = nil
        loop do
          buffer = 0.chr * buffer_count
          length_or_buffer_count = yield(buffer)
          if 0 == length_or_buffer_count
            yield(nil)
          elsif buffer_count < length_or_buffer_count
            # once or twice is usually reasonable. if the required buffer is
            # strictly non-decreasing and unsatisfiable on each call to the API
            # then something is wrong.
            try_count += 1
            if try_count > max_tries
              raise ::RightScale::Exceptions::PlatformError,
                    "Infinite loop detected in API retry after #{max_tries} attempts."
            end
            if length_or_buffer_count > max_buffer_size
              raise ::RightScale::Exceptions::PlatformError,
                    "API requested unexpected buffer size = #{length_or_buffer_count}"
            end
            buffer_count = length_or_buffer_count
          else
            buffer = buffer[0, length_or_buffer_count]
            break
          end
        end
        buffer
      end

    end

    class Filesystem

      # constants

      # Windows-defined maximum path length for legacy Windows APIs that
      # restrict path buffer sizes by default.
      MAX_PATH = 260

      SYMBOLIC_LINK_FLAG_DIRECTORY = 0x1  # @see CreateSymbolicLink function

      # this can change because companies get bought and managers insist on
      # using the current company name for some reason (better learn that or
      # else you will be finding and fixing all the hardcoded company names).
      COMPANY_DIR_NAME = 'RightScale'

      # Overrides base Filesystem#find_executable_in_path
      def find_executable_in_path(command_name)
        # must search all known (executable) path extensions unless the
        # explicit extension was given. this handles a case such as 'curl'
        # which can either be on the path as 'curl.exe' or as a command shell
        # shortcut called 'curl.cmd', etc.
        use_path_extensions = 0 == ::File.extname(command_name).length
        path_extensions = use_path_extensions ? ::ENV['PATHEXT'].split(/;/) : nil

        # must check the current working directory first just to be completely
        # sure what would happen if the command were executed. note that linux
        # ignores the CWD, so this is platform-specific behavior for windows.
        cwd = ::Dir.getwd
        path = ::ENV['PATH']
        path = (path.nil? || 0 == path.length) ? cwd : (cwd + ';' + path)
        path.split(/;/).each do |dir|
          if use_path_extensions
            path_extensions.each do |path_extension|
              path = pretty_path(::File.join(dir, command_name + path_extension))
              return path if ::File.executable?(path)
            end
          else
            path = pretty_path(::File.join(dir, command_name))
            return path if ::File.executable?(path)
          end
        end
        return nil
      end

      # Convenience method for pretty common appdata dir and for mocking what is
      # normally a Dir constant during test.
      #
      # @return [String] pretty common application data dir
      def common_app_data_dir
        @common_app_data_dir ||= pretty_path(::Dir::COMMON_APPDATA)
      end

      # Convenience method for pretty program files (x86) dir and for mocking
      # what is normally a Dir constant during test.
      #
      # @return [String] pretty program files (x86) dir
      def program_files_dir
        @program_files_dir ||= pretty_path(::Dir::PROGRAM_FILES)
      end

      # Common app data for all products of this company (whose name is not
      # necessarily a constant because companies get bought, you know).
      #
      # @return [String] company common application data dir
      def company_app_data_dir
        @company_app_data_dir ||= ::File.join(common_app_data_dir, COMPANY_DIR_NAME)
      end

      # Program files base for all products of this company.
      #
      # @return [String] path to installed RightScale directory
      def company_program_files_dir
        @company_program_files_dir ||= ::File.join(program_files_dir, COMPANY_DIR_NAME)
      end

      # @return [String] system root
      def system_root
        @system_root ||= pretty_path(::ENV['SystemRoot'])
      end

      # Home directory for user settings and documents or else the temp dir if
      # undefined.
      #
      # @return [String] user home
      def user_home_dir
        @user_home_dir ||= pretty_path(::ENV['USERPROFILE'] || temp_dir)
      end

      # Overrides base Filesystem#right_agent_cfg_dir
      def right_agent_cfg_dir
        @right_agent_cfg_dir ||= ::File.join(company_app_data_dir, 'right_agent')
      end

      # Overrides base Filesystem#right_scale_static_state_dir
      def right_scale_static_state_dir
        @right_scale_static_state_dir ||= ::File.join(company_app_data_dir, 'rightscale.d')
      end

      # Overrides base Filesystem#right_link_static_state_dir
      def right_link_static_state_dir
        @right_link_static_state_dir ||= ::File.join(right_scale_static_state_dir, 'right_link')
      end

      # Overrides base Filesystem#right_link_dynamic_state_dir
      def right_link_dynamic_state_dir
        @right_link_dynamic_state_dir ||= ::File.join(company_app_data_dir, 'right_link')
      end

      # Overrides base Filesystem#spool_dir
      def spool_dir
        @spool_dir ||= ::File.join(company_app_data_dir, 'spool')
      end

      # Overrides base Filesystem#ssh_cfg_dir
      def ssh_cfg_dir
        @ssh_cfg_dir ||= ::File.join(user_home_dir, '.ssh')
      end

      # Overrides base Filesystem#cache_dir
      def cache_dir
        @cache_dir ||= ::File.join(company_app_data_dir, 'cache')
      end

      # Overrides base Filesystem#log_dir
      def log_dir
        @log_dir ||= ::File.join(company_app_data_dir, 'log')
      end

      # Overrides base Filesystem#source_code_dir
      def source_code_dir
        @source_code_dir ||= ::File.join(company_app_data_dir, 'src')
      end

      # Overrides base Filesystem#temp_dir
      def temp_dir
        # Dir.tmpdir has historically had some odd behavior when running as
        # SYSTEM so our legacy behavior is to prefer the API call. specifically
        # the Dir.tmpdir doesn't necessarily exist but GetTempPath dir always
        # exists. calling Dir.mktmpdir is reliable because it creates tmpdir.
        unless @temp_dir
          # MAX_PATH + (trailing backslash); see API documentation.
          data = with_resizable_buffer(MAX_PATH + 1) do |buffer|
            if buffer
              GetTempPath(buffer.size, buffer)
            else
              raise ::RightScale::Platform::Win32Error, 'Failed to query temp path'
            end
          end

          # note that temp path is documented as always having a trailing slash
          # but a defensive programmer never trusts that 'always' remark so use
          # a conditional chomp.
          @temp_dir = pretty_path(data.chomp('\\'))
        end
        @temp_dir
      end

      # Overrides base Filesystem#pid_dir
      def pid_dir
        @pid_dir ||= ::File.join(company_app_data_dir, 'run')
      end

      # @return [String] installed RightLink directory path
      def right_link_home_dir
        @right_link_home_dir ||=
          ::File.normalize_path(
            pretty_path(
              ::ENV['RS_RIGHT_LINK_HOME'] ||
              ::File.join(company_program_files_dir, 'RightLink')))
      end

      # Overrides base Filesystem#private_bin_dir
      def private_bin_dir
        @private_bin_dir ||= ::File.join(right_link_home_dir, 'bin')
      end

      # Overrides base Filesystem#sandbox_dir
      def sandbox_dir
        @sandbox_dir ||= ::File.join(right_link_home_dir, 'sandbox')
      end

      # Overrides base Filesystem#long_path_to_short_path
      #
      # Converts a long path to a short path. In Windows terms this means taking
      # any file/folder name over 8 characters in length and truncating it to
      # six (6) characters with ~1..~n appended depending on how many similar
      # names exist in the same directory. File extensions are simply chopped
      # at three (3) letters. The short name is equivalent for all API calls to
      # the long path but requires no special quoting, etc. Windows APIs are
      # also subject to the MAX_PATH limitation (due to originally being
      # designed to run on 16-bit DOS) unless special 32KB path extenders (i.e.
      # prepending "\\?\" to input paths) are used. Converting paths from long
      # to short paths makes file APIs alot less likely to fail with a path
      # length error. Note that it is possible to configure an NTFS volume to
      # not support short-paths (i.e. only long paths are kept by the file
      # system) in which case this method will always return the long path (and
      # probably lead to lots of path length errors).
      def long_path_to_short_path(long_path)
        result = nil
        if ::File.exists?(long_path)
          query_path = long_path + 0.chr  # ensure nul-terminated
          data = with_resizable_buffer do |buffer|
            if buffer
              GetShortPathName(query_path, buffer, buffer.size)
            else
              raise ::RightScale::Platform::Win32Error,
                    "Failed to query short path for #{long_path.inspect}"
            end
          end
          result = pretty_path(data)
        else
          # must get short path for any existing ancestor since child doesn't
          # (currently) exist.
          child_name = File.basename(long_path)
          long_parent_path = File.dirname(long_path)

          # note that root dirname is root itself (at least in windows)
          if long_path == long_parent_path
            result = long_path
          else
            # recursion
            short_parent_path = long_path_to_short_path(::File.dirname(long_path))
            result = ::File.join(short_parent_path, child_name)
          end
        end
        result
      end

      # Overrides base Filesystem#pretty_path
      #
      # pretties up paths which assists Dir.glob() and Dir[] calls which will
      # return empty if the path contains any \ characters. windows doesn't
      # care (most of the time) about whether you use \ or / in paths. as
      # always, there are exceptions to this rule (such as "del c:/xyz" which
      # fails while "del c:\xyz" succeeds)
      def pretty_path(path, native_fs_flag = false)
        result = nil
        if native_fs_flag
          result = path.gsub('/', "\\").gsub(/\\+/, "\\")
        else
          result = path.gsub("\\", '/').gsub(/\/+/, '/')
        end
        result
      end

      # Ensures a local drive location for the file or folder given by path
      # by copying to a local temp directory given by name only if the item
      # does not appear on the home drive. This method is useful because
      # secure applications refuse to run scripts from network locations, etc.
      # Replaces any similar files in temp dir to ensure latest updates.
      #
      # @param [String] path to file or directory to be placed locally
      # @param [String] temp_dir_name as relative path of temp directory to
      #   use only if the file or folder is not on a local drive.
      #
      # @return [String] local drive path
      def ensure_local_drive_path(path, temp_dir_name)
        homedrive = ::ENV['HOMEDRIVE']
        if homedrive && homedrive.upcase != path[0,2].upcase
          local_dir = ::File.join(temp_dir, temp_dir_name)
          ::FileUtils.mkdir_p(local_dir)
          local_path = ::File.join(local_dir, ::File.basename(path))
          if ::File.directory?(path)
            ::FileUtils.rm_rf(local_path) if ::File.directory?(local_path)
            ::FileUtils.cp_r(::File.join(path, '.'), local_path)
          else
            ::FileUtils.cp(path, local_path)
          end
          path = local_path
        end
        return path
      end

      # Overrides base Filesystem#create_symlink
      #
      # Ruby on Windows does not support File.symlink. Windows 2008 Server and
      # newer versions of Windows do support the CreateSymbolicLink API.
      def create_symlink(from_path, to_path)

        # TEAL FIX this actually requires the SE_CREATE_SYMBOLIC_LINK_NAME
        # privilege to be held, but because the agent always runs elevated we
        # have never had to acquire it.
        flags = ::File.directory?(from_path) ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0
        symlink_file_path = to_path + 0.chr
        target_file_path = from_path + 0.chr
        unless CreateSymbolicLink(symlink_file_path, target_file_path, flags)
          raise ::RightScale::Platform::Win32Error,
                "Failed to create link from #{from_path.inspect} to #{to_path.inspect}"
        end
        0 # zero to emulate File.symlink
      end

      # :bool CreateSymbolicLink(:buffer_in, :buffer_in, :dword)
      #
      # CreateSymbolicLink function
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa363866%28v=vs.85%29.aspx
      #
      # @param [String] symlink_file_path for symlinking
      # @param [String] target_file_path for symlinking
      # @param [Integer] flags for symlinking
      #
      # @return [TrueClass|FalseClass] true if successful
      def CreateSymbolicLink(symlink_file_path, target_file_path, flags)
        must_be_overridden
      end

      # :dword GetShortPathName(:buffer_in, :buffer_out, :dword)
      #
      # GetShortPathName function
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa364989%28v=vs.85%29.aspx
      #
      # @param [String] long_path for query
      # @param [String] short_path_buffer to be filled
      # @param [String] short_path_buffer_length as limit
      #
      # @return [Integer] zero on failure or length or required buffer size
      def GetShortPathName(long_path, short_path_buffer, short_path_buffer_length)
        must_be_overridden
      end

      # :dword GetTempPath(:dword, :buffer_out)
      #
      # GetTempPath function
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa364992%28v=vs.85%29.aspx
      #
      # @param [Integer] buffer_length as limit in chars
      # @param [String] buffer to be filled
      #
      # @return [Integer] zero on failure or length or required buffer size
      def GetTempPath(buffer_length, buffer)
        must_be_overridden
      end
    end # Filesystem

    # Provides utilities for managing volumes (disks).
    class VolumeManager
      def initialize
        @assignable_disk_regex = /^[D-Zd-z]:[\/\\]?$/
        @assignable_path_regex = /^[A-Za-z]:[\/\\][\/\\\w\s\d\-_\.~]+$/
      end

      # Determines if the given path is valid for a Windows volume attachemnt
      # (excluding the reserved A: B: C: drives).
      #
      # @return [TrueClass|FalseClass] true if path is a valid volume root
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
      # @param [Hash] conditions to match or nil or empty (Default = no conditions)
      #
      # @return [Array] array of volume info hashes detailing visible disks
      #
      # @raise [VolumeError] on failure to list disks
      # @raise [ParserError] on failure to parse disks from output
      def disks(conditions = nil)
        script = <<EOF
rescan
list disk
EOF
        output_text = run_diskpart_script(script, 'list disks')
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
      # @param [Hash] conditions to match or nil or empty (Default = no conditions)
      #
      # @return [Array] array of volume info hashes detailing visible volumes
      #
      # @raise [VolumeError] on failure to list volumes
      # @raise [ParserError] on failure to parse volumes from output
      def volumes(conditions = nil)
        script = <<EOF
rescan
list volume
EOF
        output_text = run_diskpart_script(script, 'list volumes')
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
      # @param [Integer] disk index to query
      # @param [Hash] conditions to match or nil or empty (Default = no conditions)
      #
      # @return [Array] list of partitions or empty
      #
      # @raise [VolumeError] on failure to list partitions
      # @raise [ParserError] on failure to parse partitions from output
      def partitions(disk_index, conditions = nil)
         script = <<EOF
rescan
select disk #{disk_index}
list partition
EOF
        output_text = run_diskpart_script(script, 'list partitions')
        return parse_partitions(output_text, conditions)
      end

      # Formats a disk given by disk index and the device (e.g. "D:") for the
      # volume on the primary NTFS partition which will be created.
      #
      # @param [Integer] disk_index as zero-based disk index (from disks list, etc.)
      # @param [String] device as disk letter or mount path specified for the volume to create
      #
      # @return [TrueClass] always true
      #
      # @raise [ArgumentError] on invalid parameters
      # @raise [VolumeError] on failure to format
      def format_disk(disk_index, device)
        if device.match(@assignable_path_regex) && os_version.major < 6
          raise ArgumentError.new("Mount path assignment is not supported in this version of windows")
        end
        # note that creating the primary partition automatically creates and
        # selects a new volume, which can be assigned a letter before the
        # partition has actually been formatted.
        raise ArgumentError.new("Invalid index = #{disk_index}") unless disk_index >= 0
        raise ArgumentError.new("Invalid device = #{device}") unless is_attachable_volume_path?(device)

        # note that Windows 2003 server version of diskpart doesn't support
        # format so that has to be done separately.
        format_command = (os_version.major < 6) ? '' : 'format FS=NTFS quick'
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
        run_diskpart_script(script, 'format disk')

        # must format using command shell's FORMAT command before 2008 server.
        if os_version.major < 6
          command = "echo Y | format #{device[0,1]}: /Q /V: /FS:NTFS"
          begin
            execute(command)
          rescue ::RightScale::Platform::CommandError => e
            raise VolumeError,
                  "Failed to format disk #{disk_index} for device #{device}: #{e.message}\n#{e.output_text}"
          end
        end
        true
      end

      # Brings the disk given by index online and clears the readonly
      # attribute, if necessary. The latter is required for some kinds of
      # disks to online successfully and SAN volumes may be readonly when
      # initially attached. As this change may bring additional volumes online
      # the updated volumes list is returned.
      #
      # @param [Integer] disk_index as zero-based disk index
      # @param [Hash] options for online
      # @option options [TrueClass|FalseClass] :idempotent true to check the
      #   current disk statuses before attempting to online the disk and bails
      #   out when disk is already online (Default = false)
      #
      # @return [TrueClass] always true
      #
      # @raise [ArgumentError] on invalid parameters
      # @raise [VolumeError] on failure to online disk
      # @raise [ParserError] on failure to parse disk list
      def online_disk(disk_index, options = {})
        raise ArgumentError.new("Invalid disk_index = #{disk_index}") unless disk_index >= 0
        # Set some defaults for backward compatibility, allow user specified options to override defaults
        options = { :idempotent => false }.merge(options)
        script = <<EOF
rescan
list disk
select disk #{disk_index}
#{get_clear_readonly_command('disk')}
#{get_online_disk_command}
EOF

        if options[:idempotent]
          disk = disks(:index => disk_index).first
          return true if disk && disk[:status] == 'Online'
        end

        run_diskpart_script(script, 'online disk')
        true
      end

      # Brings the disk given by index offline
      #
      # @param [Integer] disk_index as zero-based disk index
      #
      # @return [TrueClass] always true
      #
      # @raise [ArgumentError] on invalid parameters
      # @raise [VolumeError] on failure to offline disk
      # @raise [ParserError] on failure to parse disk list
      # @raise [RightScale::Exceptions::PlatformError] if offline unsupported
      def offline_disk(disk_index)
        raise ArgumentError.new("Invalid disk_index = #{disk_index}") unless disk_index >= 0
        if os_version.major < 6
          raise ::RightScale::Exceptions::PlatformError,
                'Offline disk is not supported by this platform'
        end

        # Set some defaults for backward compatibility, allow user specified options to override defaults
        script = <<EOF
rescan
list disk
select disk #{disk_index}
offline disk noerr
EOF

        run_diskpart_script(script, 'offline disk')
        true
      end

      # Assigns the given device name to the volume given by index and clears
      # the readonly attribute, if necessary. The device must not currently be
      # in use.
      #
      # @param [Integer|String] volume_device_or_index as old device or
      #   zero-based volume index (from volumes list, etc.) to select for
      #   assignment.
      # @param [String] device as disk letter or mount path specified for the
      #   volume to create
      # @param [Hash] options for assignment
      # @option options [TrueClass|FalseClass] :clear_readonly if true will
      #   clear the volume readonly flag if set (Default = true)
      # @option options [TrueClass|FalseClass] :remove_all if true will remove
      #   all previously assigned devices and paths, essentially a big RESET
      #   button for volume assignment (Default = false)
      # @option options [TrueClass|FalseClass] :idempotent if true will checks
      #   the current device assignments before assigning the device according
      #   to the specified parameters and bails out if already assigned
      #   (Default = false)
      #
      # @return [TrueClass] always true
      #
      # @raise [ArgumentError] on invalid parameters
      # @raise [VolumeError] on failure to assign device name
      # @raise [ParserError] on failure to parse volume list
      def assign_device(volume_device_or_index, device, options = {})
        # Set some defaults for backward compatibility, allow user specified options to override defaults
        options = {
          :clear_readonly => true,
          :remove_all     => false,
          :idempotent     => false
        }.merge(options)
        if device.match(@assignable_path_regex) && os_version.major < 6
          raise ArgumentError.new('Mount path assignment is not supported in this version of windows')
        end
        # Volume selector for drive letter assignments
        volume_selector_match = volume_device_or_index.to_s.match(/^([D-Zd-z]|\d+):?$/)
        # Volume selector for mount path assignments
        volume_selector_match = volume_device_or_index.to_s.match(@assignable_path_regex) unless volume_selector_match
        raise ArgumentError.new("Invalid volume_device_or_index = #{volume_device_or_index}") unless volume_selector_match
        volume_selector = volume_selector_match[1]
        raise ArgumentError.new("Invalid device = #{device}") unless is_attachable_volume_path?(device)
        if options[:idempotent]
          # Device already assigned?
          already_assigned = volumes.any? do |volume|
            volume[:device] == device &&
            (volume[:index] == volume_device_or_index.to_s ||
             volume[:device] == volume_device_or_index.to_s)
          end
          return true if already_assigned
        end
        # Validation ends here, and real stuff starts to happen

        script = <<EOF
rescan
list volume
select volume "#{volume_selector}"
#{get_clear_readonly_command('volume') if options[:clear_readonly]}
#{'remove all noerr' if options[:remove_all]}
#{get_assign_command_for_device(device)}
EOF
        run_diskpart_script(script, 'assign device')
        true
      end

      private

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
      # @param [String] output_text raw output from diskpart
      # @param [Hash] conditions as hash of conditions to match or empty or nil (Default = no conditions)
      #
      # @return [Array] disks or empty
      #
      # @raise [ParserError] on failure to parse disk list
      def parse_disks(output_text, conditions = nil)
        result = []
        line_regex = nil
        header_regex = /  --------  (-+)  -------  -------  ---  ---/
        header_match = nil
        output_text.lines.each do |line|
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
      # @param [String] output_text as raw output from diskpart
      # @param [Hash] conditions as hash of conditions to match or empty or nil (Default = no conditions)
      #
      # @return [Array] volumes or empty. Drive letters are appended with ':'
      #   even though they aren't returned that way from diskpart
      #
      # @raise [ParserError] on failure to parse volume list
      def parse_volumes(output_text, conditions = nil)
        result = []
        header_regex = /  ----------  ---  (-+)  (-+)  (-+)  -------  (-+)  (-+)/
        header_match = nil
        line_regex = nil
        output_text.lines.each do |line|
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
      # @param [String] output_text as raw output from diskpart
      # @param [Hash] conditions as hash of conditions to match or empty or nil (Default = no conditions)
      #
      # @return [Array] volumes or empty
      #
      # @raise [ParserError] on failure to parse partition list
      def parse_partitions(output_text, conditions = nil)
        result = []
        header_regex = /  -------------  (-+)  -------  -------/
        header_match = nil
        line_regex = nil
        output_text.lines.each do |line|
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

      # Determines if the given value is empty and returns nil in that case.
      #
      # @param [String] value to check
      #
      # @return [String] trimmed value or nil
      def nil_if_empty(value)
        value = value.strip
        return nil if value.empty?
        return value
      end

      # Multiplies a raw size value by a size factor given as a standardized
      # bytes acronym.
      #
      # @param [String|Number] size_by value to multiply
      # @param [String] size_factor multiplier acronym
      #
      # @return [Integer] bytes
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
      # @param [String] device as either a drive letter or mount path
      #
      # @return [String] the correct diskpart assignment command
      def get_assign_command_for_device(device)
        if device.match(@assignable_disk_regex)
          "assign letter=#{device[0,1]}"
        elsif device.match(@assignable_path_regex)
          "assign mount=\"#{device}\""
        end
      end

      # Returns the correct 'online disk' diskpart command based on the OS version
      #
      # @return [String] either "online noerr" or "online disk noerr" depending upon the OS version
      def get_online_disk_command
        (os_version.major < 6) ? 'online noerr' : 'online disk noerr'
      end

      # Returns the correct 'attribute disk clear readonly' diskpart command based on the OS version
      #
      # @param [String] object_type as one of "disk" or "volume" to clear read only for
      #
      # @return [String] either a blank string or "attribute #{object_type} clear readonly noerr" depending upon the OS version
      def get_clear_readonly_command(object_type)
        (os_version.major < 6) ? '' : "attribute #{object_type} clear readonly noerr"
      end

      private

      # Run a diskpart script and get the exit code and text output. See also
      # technet and search for "DiskPart Command-Line Options" or else
      # "http://technet.microsoft.com/en-us/library/cc766465%28WS.10%29.aspx".
      # Note that there are differences between 2003 and 2008 server versions
      # of this utility.
      #
      # @param [String] script with commands delimited by newlines
      # @param [String] context for exception on failure
      #
      # @return [String] output from diskpart
      #
      # @raise [VolumeError] on diskpart script failure
      def run_diskpart_script(script_text, context)
        ::Dir.mktmpdir do |temp_dir_path|
          script_file_path = File.join(temp_dir_path, 'rs_diskpart_script.txt')
          ::File.open(script_file_path, 'w') { |f| f.puts(script_text.strip) }
          executable_path = 'diskpart.exe'
          executable_arguments = ['/s', ::File.normalize_path(script_file_path)]
          shell = ::RightScale::Platform.shell
          executable_path, executable_arguments = shell.format_right_run_path(executable_path, executable_arguments)
          command = shell.format_executable_command(executable_path, executable_arguments)
          execute(command)
        end
      rescue ::RightScale::Platform::CommandError => e
        raise VolumeError,
              "Failed to #{context}: #{e.message}\nScript =\n#{script_text}\nOutput = #{e.output_text}"
      end

      # Caches result from os info query. Convenient for mocking under test.
      def os_version
        @os_version ||= ::RightScale::Platform.windows_system_information.version
      end

    end # VolumeManager

    # Provides utilities for formatting executable shell commands, etc.
    class Shell
      POWERSHELL_V1x0_EXECUTABLE_PATH = 'powershell.exe'
      POWERSHELL_V1x0_SCRIPT_EXTENSION = '.ps1'
      RUBY_SCRIPT_EXTENSION = '.rb'

      # defined for backward compatibility; use Shell#null_output_name
      NULL_OUTPUT_NAME = 'NUL'

      # Overrides base Shell#null_output_name
      def null_output_name
        NULL_OUTPUT_NAME
      end

      # Overrides base Shell#format_script_file_name
      def format_script_file_name(partial_script_file_path, default_extension = nil)
        default_extension ||= POWERSHELL_V1x0_SCRIPT_EXTENSION
        extension = ::File.extname(partial_script_file_path)
        if 0 == extension.length
          return partial_script_file_path + default_extension
        end

        # quick out for default extension.
        if 0 == (extension <=> default_extension)
          return partial_script_file_path
        end

        # confirm that the "extension" is really something understood by
        # the command shell as being executable.
        if executable_extensions.include?(extension.downcase)
          return partial_script_file_path
        end

        # not executable; use default extension.
        return partial_script_file_path + default_extension
      end

      # Overrides base Shell#format_shell_command
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

      # Overrides base Shell#sandbox_ruby
      def sandbox_ruby
        unless @sandbox_ruby
          filesystem = ::RightScale::Platform.filesystem
          @sandbox_ruby =
            ::File.normalize_path(
              filesystem.pretty_path(
                ::ENV['RS_RUBY_EXE'] ||
                ::File.join(filesystem.sandbox_dir, 'ruby', 'bin', 'ruby.exe')))
        end
      end

      # Overrides base Shell#uptime
      def uptime
        (::Time.now.to_i.to_f - booted_at.to_f) rescue 0.0
      end

      # Overrides base Shell#booted_at
      def booted_at
        begin
          # the tmpdir is for Windows Server 2003 behavior where a turd file was
          # created in the working directory when wmic was invoked.
          wmic_output = nil
          ::Dir.mktmpdir do |temp_dir_path|
            ::Dir.chdir(temp_dir_path) do
              wmic_output = execute('echo | wmic OS Get LastBootUpTime 2>&1')
            end
          end
          match = /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.\d{6}([+-]\d{3})/.match(wmic_output)

          year, mon, day, hour, min, sec, tz = match[1..-1]

          # convert timezone from [+-]mmm to [+-]hh:mm
          tz = "#{tz[0...1]}#{(tz.to_i.abs / 60).to_s.rjust(2,'0')}:#{(tz.to_i.abs % 60).to_s.rjust(2,'0')}"

          # finally, parse the WMIC output as an XML-schema time, which is the
          # only reliable way to parse a time with arbitrary zone in Ruby (?!)
          return Time.xmlschema("#{year}-#{mon}-#{day}T#{hour}:#{min}:#{sec}#{tz}").to_i
        rescue ::RightScale::Platform::CommandError
          return nil
        end
      end

      # Formats an executable path and arguments by inserting a reference to
      # RightRun.exe only when necessary.
      #
      # @param [String] executable_file_path for formatting
      # @param [Array] arguments for command or empty
      #
      # @return [Array] tuple for updated [executable_path, executable_arguments]
      def format_right_run_path(executable_file_path, executable_arguments)
        unless right_run_path.empty?
          executable_arguments.unshift(executable_file_path)
          executable_file_path = right_run_path
        end

        return executable_file_path, executable_arguments
      end


      # Formats an executable command by quoting any of the arguments as
      # needed and building an executable command string.
      #
      # @param [String] executable_file_path for formatting
      # @param [Array] arguments for command or empty
      #
      # @return [String] executable command string
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
          escaped.join(' ')
        end
      end

      # Formats a powershell command using the given script path and arguments.
      # Allows for specifying powershell from a specific installed location.
      # This method is only implemented for Windows.
      #
      # @param [String] shell_script_file_path for formatting
      # @param [Array] arguments for command or empty
      #
      # @return [String] executable command string
      def format_powershell_command(shell_script_file_path, *arguments)
        return format_powershell_command4(
          POWERSHELL_V1x0_EXECUTABLE_PATH,
          lines_before_script = nil,
          lines_after_script = nil,
          shell_script_file_path,
          *arguments)
      end

      # Formats a powershell command using the given script path and arguments.
      # Allows for specifying powershell from a specific installed location.
      # This method is only implemented for Windows.
      #
      # @param [String] powershell_exe_path for formatting
      # @param [String] shell_script_file_path for formatting
      # @param [Array] arguments for command or empty
      #
      # @return [String] executable command string
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
        lines_before_script.insert(0, 'set-executionpolicy -executionPolicy RemoteSigned -Scope Process')

        # insert error checking only in case of defaulted "lines after script"
        # to be backward compatible with existing scripts.
        if defaulted_lines_after_script
          # ensure for a generic powershell script that any errors left in the
          # global $Error list are noted and result in script failure. the
          # best practice is for the script to handle errors itself (and clear
          # the $Error list if necessary), so this is a catch-all for any
          # script which does not handle errors "properly".
          lines_after_script << 'if ($NULL -eq $LastExitCode) { $LastExitCode = 0 }'
          lines_after_script << "if ((0 -eq $LastExitCode) -and ($Error.Count -gt 0)) { $RS_message = 'Script exited successfully but $Error contained '+($Error.Count)+' error(s):'; write-output $RS_message; write-output $Error; $LastExitCode = 1 }"
        end

        # ensure last exit code gets marshalled.
        marshall_last_exit_code_cmd = 'exit $LastExitCode'
        if defaulted_lines_after_script || (lines_after_script.last != marshall_last_exit_code_cmd)
          lines_after_script << marshall_last_exit_code_cmd
        end

        # format powershell command string.
        powershell_command = "&{#{lines_before_script.join('; ')}; &#{escaped.join(' ')}; #{lines_after_script.join('; ')}}"

        # in order to run 64-bit powershell from this 32-bit ruby process, we need to launch it using
        # our special RightRun utility from program files, if it is installed (it is not installed for
        # 32-bit instances and perhaps not for test/dev environments).
        executable_path = powershell_exe_path
        executable_arguments = ['-command', powershell_command]
        executable_path, executable_arguments = format_right_run_path(executable_path, executable_arguments)

        # combine command string with powershell executable and arguments.
        return format_executable_command(executable_path, executable_arguments)
      end

      # @return [Array] list of dot-prefixed executable file extensions from PATHEXT
      def executable_extensions
        @executable_extensions ||= ::ENV['PATHEXT'].downcase.split(';')
      end

      # @return [String] path to RightRun.exe or empty in cases where it is unneeded
      def right_run_path
        unless @right_run_path
          @right_run_path = ''
          if ::ENV['ProgramW6432'] && (@right_run_path = ::ENV['RS_RIGHT_RUN_EXE'].to_s).empty?
            temp_path = ::File.join(
              ::ENV['ProgramW6432'],
              ::RightScale::Platform::Filesystem::COMPANY_DIR_NAME,
              'Shared',
              'RightRun.exe')
            if ::File.file?(temp_path)
              @right_run_path = ::File.normalize_path(temp_path).gsub('/', "\\")
            end
          end
        end
        @right_run_path
      end
    end # Shell

    class Controller

      TOKEN_ADJUST_PRIVILEGES = 0x0020

      TOKEN_QUERY = 0x0008

      SE_PRIVILEGE_ENABLED = 0x00000002

      # Overrides base Controller#reboot
      def reboot
        initiate_system_shutdown(true)
      end

      # Overrides base Controller#shutdown
      def shutdown
        initiate_system_shutdown(false)
      end

      def initiate_system_shutdown(reboot_after_shutdown)
        # APIs
        process = ::RightScale::Platform.process
        windows_common = ::RightScale::Platform.windows_common
        windows_security = ::RightScale::Platform.windows_security

        # get current process token.
        token_handle = 0.chr * 4
        unless process.OpenProcessToken(
                  process_handle = process.GetCurrentProcess(),
                  desired_access = TOKEN_ADJUST_PRIVILEGES + TOKEN_QUERY,
                  token_handle)
          raise ::RightScale::Platform::Win32Error,
                'Failed to open process token'
        end
        token_handle = token_handle.unpack('V')[0]

        begin
          # lookup shutdown privilege ID.
          luid = 0.chr * 8
          unless windows_security.LookupPrivilegeValue(
                    system_name = nil,
                    priviledge_name = 'SeShutdownPrivilege' + 0.chr,
                    luid)
            raise ::RightScale::Platform::Win32Error,
                  'Failed to lookup shutdown privilege'
          end
          luid = luid.unpack('VV')

          # adjust token privilege to enable shutdown.
          token_privileges       = 0.chr * 16                        # TOKEN_PRIVILEGES tokenPrivileges;
          token_privileges[0,4]  = [1].pack('V')                     # tokenPrivileges.PrivilegeCount = 1;
          token_privileges[4,8]  = luid.pack('VV')                   # tokenPrivileges.Privileges[0].Luid = luid;
          token_privileges[12,4] = [SE_PRIVILEGE_ENABLED].pack('V')  # tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
          unless windows_security.AdjustTokenPrivileges(
                    token_handle, disable_all_privileges = false,
                    token_privileges, buffer_length = 0,
                    previous_state = nil, return_length = nil)
            raise ::RightScale::Platform::Win32Error,
                  'Failed to adjust token privileges'
          end
          unless InitiateSystemShutdown(machine_name = nil,
                                        message = nil,
                                        timeout_secs = 1,
                                        force_apps_closed = true,
                                        reboot_after_shutdown)
            raise ::RightScale::Platform::Win32Error,
                  'Failed to initiate system shutdown'
          end
        ensure
          windows_common.CloseHandle(token_handle)
        end
        true
      end

      # :bool InitiateSystemShutdown(:string, :string, :dword, :bool, :bool)
      #
      # InitiateSystemShutdown function
      # @see http://msdn.microsoft.com/en-us/library/aa376873%28v=VS.85%29.aspx
      #
      # @param [String] machine_name for shutdown or nil
      # @param [String] message for shutdown or nil
      # @param [Integer] timeout for shutdown or 0
      # @param [TrueClass|FalseClass] force_apps_closed as true to forcibly close applications
      # @param [TrueClass|FalseClass] reboot_after_shutdown as true to restart immediately after shutting down
      #
      # @return [TrueClass|FalseClass] true if successful
      def InitiateSystemShutdown(machine_name, message, timeout, force_apps_closed, reboot_after_shutdown)
        must_be_overridden
      end

    end # Controller

    class Rng

      # Overrides base Rng#pseudorandom_bytes
      def pseudorandom_bytes(count)
        bytes = ''
        count.times { bytes << rand(0xff) }
        bytes
      end
    end

    class Process

      # Overrides base Process#resident_set_size
      def resident_set_size(pid = nil)
        # TEAL NOTE no use case for getting memory info for non-current process.
        raise ::NotImplementedError.new('pid != nil not yet implemented') if pid

        buffer = create_process_memory_counters
        unless GetProcessMemoryInfo(GetCurrentProcess(), buffer, buffer.bytesize)
          raise ::RightScale::Platform::Win32Error,
                'Failed to get resident set size for process'
        end

        # PROCESS_MEMORY_COUNTERS.WorkingSetSize (bytes) is equivalent of Linux'
        # ps resident set size (KB).
        process_memory_counters = unpack_process_memory_counters(buffer)
        resident_set_size_bytes = process_memory_counters[3]
        resident_set_size_bytes / 1024  # bytes to KB
      end

      # PROCESS_MEMORY_COUNTERS structure
      # @see http://msdn.microsoft.com/en-us/library/ms684877%28VS.85%29.aspx
      #
      # @return [String] initialized PROCESS_MEMORY_COUNTERS structure
      def create_process_memory_counters
        [
          40,  # size of PROCESS_MEMORY_COUNTERS (IN)
          0,   # PageFaultCount (OUT)
          0,   # PeakWorkingSetSize (OUT)
          0,   # WorkingSetSize (OUT)
          0,   # QuotaPeakPagedPoolUsage (OUT)
          0,   # QuotaPagedPoolUsage (OUT)
          0,   # QuotaPeakNonPagedPoolUsage (OUT)
          0,   # QuotaNonPagedPoolUsage (OUT)
          0,   # PagefileUsage (OUT)
          0    # PeakPagefileUsage (OUT)
        ].pack('LLLLLLLLLL')
      end

      # @param [String] buffer to unpack
      #
      # @return [Array] unpacked PROCESS_MEMORY_COUNTERS members
      def unpack_process_memory_counters(buffer)
        buffer.unpack('LLLLLLLLLL')
      end

      # :handle GetCurrentProcess()
      #
      # GetCurrentProcess function
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/ms683179%28v=vs.85%29.aspx
      #
      # @return [Integer] current process handle
      def GetCurrentProcess
        must_be_overridden
      end

      # :bool GetProcessMemoryInfo(:handle, :buffer_out, :dword)
      #
      # GetProcessMemoryInfo function
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/ms683219%28v=vs.85%29.aspx
      #
      # @param [Integer] process_handle for query
      # @param [String] process_memory_info_buffer for response
      # @param [String] process_memory_info_buffer_size as limit
      #
      # @return [TrueClass|FalseClass] true if successful
      def GetProcessMemoryInfo(process_handle, process_memory_info_buffer, process_memory_info_buffer_size)
        must_be_overridden
      end

      # :bool OpenProcessToken(:handle, :dword, :pointer)
      #
      # OpenProcessToken function
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa379295%28v=vs.85%29.aspx
      #
      # @param [Integer] process_handle for token
      # @param [Integer] desired_access for token
      # @param [String] token_handle to be returned
      #
      # @return [TrueClass|FalseClass] true if successful
      def OpenProcessToken(process_handle, desired_access, token_handle)
        must_be_overridden
      end
    end
    
    class Installer

      # Overrides base Installer#install
      def install(packages)
        raise ::RightScale::Exceptions::PlatformError,
              'No package installers supported on Windows'
      end
    end

    # Provides common Windows APIs
    class WindowsCommon < PlatformHelperBase

      # @see FormatMessage function
      FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
      FORMAT_MESSAGE_FROM_SYSTEM    = 0x00001000

      # :bool CloseHandle(:handle)
      #
      # CloseHandle function
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/ms724211%28v=vs.85%29.aspx
      #
      # @param [Integer] handle
      #
      # @return [TrueClass|FalseClass] true if succeeded
      def CloseHandle(handle)
        must_be_overridden
      end

      # :dword FormatMessage(:dword, :buffer_in, :dword, :dword, :buffer_out, :dword, :pointer)
      #
      # FormatMessage function
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/ms679351%28v=vs.85%29.aspx
      #
      # @param [Integer] flags for formatting
      # @param [String] source for formatting or nil
      # @param [Integer] message_id for formatting or zero
      # @param [Integer] language_id for formatting or zero
      # @param [String] buffer to receive formatted string
      # @param [Integer] buffer_size for buffer limit
      # @param [String] arguments for formatting or nil
      #
      # @return [Integer] length of formatted string or zero on failure
      def FormatMessage(flags, source, message_id, language_id, buffer, buffer_size, arguments)
        must_be_overridden
      end

      # :dword GetLastError()
      #
      # GetLastError function
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/ms679360%28v=vs.85%29.aspx
      #
      # @return [Integer] last error code or zero
      def GetLastError
        must_be_overridden
      end
    end

    # Provides Windows security
    class WindowsSecurity < PlatformHelperBase

      # :bool LookupPrivilegeValue(:string, :string, :pointer)
      #
      # LookupPrivilegeValue function
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa379180%28v=vs.85%29.aspx
      #
      # @param [String] system_name for lookup or nil
      # @param [String] name for lookup
      # @param [String] luid to be returned
      #
      # @return [TrueClass|FalseClass] true if successful
      def LookupPrivilegeValue(system_name, name, luid)
        must_be_overridden
      end

      # :bool AdjustTokenPrivileges(:handle, :bool, :pointer, :dword, :pointer, :pointer)
      #
      # AdjustTokenPrivileges function
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa375202%28v=vs.85%29.aspx
      #
      # @param [Integer] token_handle for adjustment
      # @param [TrueClass|FalseClass] disable_all_privileges true to disable all
      # @param [String] new_state for adjustment
      # @param [Integer] buffer_length sizeof previous_state buffer
      # @param [String] previous_state output buffer
      # @param [String] return_length output length
      #
      # @return [TrueClass|FalseClass] true if successful
      def AdjustTokenPrivileges(token_handle, disable_all_privileges, new_state, buffer_length, previous_state, return_length)
        must_be_overridden
      end
    end

    # Provides Windows system information
    class WindowsSystemInformation < PlatformHelperBase

      # System version
      class Version
        attr_reader :major, :minor, :build

        def initialize(major, minor, build)
          @major = major
          @minor = minor
          @build = build
        end

        # @return [String] stringized version
        def to_s
          [major, minor, build].join('.')
        end
      end

      def initialize
        @version = nil
        @os_version_info = nil
      end

      # @return [Version] version
      def version
        unless @version
          osvi = os_version_info
          @version = ::RightScale::Platform::WindowsSystemInformation::Version.new(
            major = osvi[1],
            minor = osvi[2],
            build = osvi[3])
        end
        @version
      end

      # @return [Array] members of queried OSVERSIONINFO struct
      def os_version_info
        unless @os_version_info
          buffer = create_os_version_info
          unless GetVersionEx(buffer)
            raise ::RightScale::Platform::Win32Error,
                  'Failed to query Windows version'
          end
          @os_version_info = unpack_os_version_info(buffer)
        end
        @os_version_info
      end

      # :bool GetVersionEx(:buffer_out)
      #
      # GetVersionEx function
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/ms724451%28v=vs.85%29.aspx
      #
      # @param [String] version_info_buffer
      #
      # @return [TrueClass|FalseClass] true if successful
      def GetVersionEx(version_info_buffer)
        must_be_overridden
      end

      # OSVERSIONINFO structure
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/ms724834%28v=vs.85%29.aspx
      #
      # @return [String] initialized buffer
      def create_os_version_info
        must_be_overridden
      end

      # @param [String] buffer to unpack
      #
      # @return [Array] unpacked OSVERSIONINFO members
      def unpack_os_version_info(buffer)
        must_be_overridden
      end
    end

    # @return [WindowsCommon] Platform-specific Windows common
    def windows_common
      platform_service(:windows_common)
    end

    # @return [WindowsSecurity] Platform-specific Windows security
    def windows_security
      platform_service(:windows_security)
    end

    # @return [WindowsSystemInformation] Platform-specific Windows system information
    def windows_system_information
      platform_service(:windows_system_information)
    end

    private

    # Overrides base Platform#initialize_genus
    def initialize_genus
      @windows_common = nil
      @windows_security = nil
      @windows_system_information = nil

      # TEAL HACK ensure GetLastError is loaded early (and also prove that the
      # platform has basic functionality) so that any just-in-time call to load
      # the API won't reset the calling thread's last error to zero (= success)
      self.windows_common.GetLastError

      # flavor and release are more for Linux but supply Windows OS info in case
      # anyone asks. pre-release (but not release) versions of Windows have
      # codenames but they are not available as system info in the same manner
      # as Linux.
      @flavor  = :windows
      @release = self.windows_system_information.version.to_s
      @codename = ''
      true
    end

  end # Platform

end # RightScale
