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

require ::File.expand_path('../../../../platform', __FILE__)

begin
  # legacy API gem for ruby 1.8, superceded by FFI in ruby 1.9
  require 'win32/api'
rescue LoadError
  # ignore unless Windows as a concession to spec testing from non-Windows.
  # any windows-only gems must be fully mocked under test.
  raise if RUBY_PLATFORM =~ /mswin/
end

module RightScale

  # Windows specific implementation
  class Platform

    # helpers
    class PlatformHelperBase
      API_NULL = 0
      API_FALSE = 0
      API_TRUE = 1

      private

      # it is incorrect in the general case to say result == API_TRUE
      # Quote from every API doc I've ever read:
      #  "If the function succeeds, the return value is nonzero"
      def api_succeeded(result)
        result != API_FALSE
      end
    end

    class Filesystem

      # Overrides base Filesystem#CreateSymbolicLink
      def CreateSymbolicLink(symlink_file_path, target_file_path, flags)
        must_be_string(symlink_file_path)
        must_be_string(target_file_path)
        must_be_dword(flags)
        @create_symbolic_link ||= ::Win32::API.new('CreateSymbolicLink', 'SSL', 'B', 'kernel32')
        api_succeeded(
          @create_symbolic_link.call(
            symlink_file_path, target_file_path, flags))
      rescue ::Win32::API::LoadLibraryError
        raise ::RightScale::Exceptions::PlatformError,
              'Cannot create symlinks on this platform'
      end

      # Overrides base Filesystem#GetShortPathName
      def GetShortPathName(long_path, short_path_buffer, short_path_buffer_length)
        must_be_string(long_path)
        must_be_char_buffer(short_path_buffer, short_path_buffer_length)
        @get_short_path_name ||= ::Win32::API.new('GetShortPathName', 'SPL', 'L', 'kernel32')
        @get_short_path_name.call(
          long_path, short_path_buffer, short_path_buffer_length)
      end

      # Overrides base Filesystem#GetTempPath
      def GetTempPath(buffer_length, buffer)
        must_be_char_buffer_or_nil(buffer, buffer_length)
        @get_temp_dir_api ||= ::Win32::API.new('GetTempPath', 'LP', 'L', 'kernel32')
        @get_temp_dir_api.call(buffer_length, buffer ? buffer : API_NULL)
      end
    end # Filesystem

    class Controller

      # Overrides base Controller#InitiateSystemShutdown
      def InitiateSystemShutdown(machine_name, message, timeout, force_apps_closed, reboot_after_shutdown)
        must_be_string_or_nil(machine_name)
        must_be_string_or_nil(message)
        must_be_dword(timeout)
        must_be_bool(force_apps_closed)
        must_be_bool(reboot_after_shutdown)
        @initiate_system_shutdown ||= ::Win32::API.new('InitiateSystemShutdown', 'PPLLL', 'B', 'advapi32')
        api_succeeded(
          @initiate_system_shutdown.call(
            machine_name ? machine_name : API_NULL,
            message ? message : API_NULL,
            timeout,
            force_apps_closed ? API_TRUE : API_FALSE,
            reboot_after_shutdown ? API_TRUE : API_FALSE))
      end
    end # Controller

    class Process

      # Overrides base Process#GetCurrentProcess
      def GetCurrentProcess
        @get_current_process ||= ::Win32::API.new('GetCurrentProcess', 'V', 'L', 'kernel32')
        @get_current_process.call
      end

      # Overrides base Process#GetProcessMemoryInfo
      def GetProcessMemoryInfo(process_handle, process_memory_info_buffer, process_memory_info_buffer_size)
        must_be_dword(process_handle)
        must_be_size_prefixed_buffer(process_memory_info_buffer, process_memory_info_buffer_size)
        @get_process_memory_info ||= ::Win32::API.new('GetProcessMemoryInfo', 'LPL', 'B', 'psapi')
        api_succeeded(
          @get_process_memory_info.call(
            process_handle,
            process_memory_info_buffer,
            process_memory_info_buffer_size))
      end

      # Overrides base Process#OpenProcessToken
      def OpenProcessToken(process_handle, desired_access, token_handle)
        must_be_dword(process_handle)
        must_be_dword(desired_access)
        must_be_byte_buffer(token_handle, SIZEOF_DWORD)
        @open_process_token ||= ::Win32::API.new('OpenProcessToken', 'LLP', 'B', 'advapi32')
        api_succeeded(
          @open_process_token.call(
            process_handle, desired_access, token_handle))
      end
    end  # Process

    class WindowsCommon

      # Overrides base WindowsCommon#CloseHandle
      def CloseHandle(handle)
        must_be_dword(handle)
        @close_handle ||= ::Win32::API.new('CloseHandle', 'L', 'B', 'kernel32')
        api_succeeded(@close_handle.call(handle))
      end

      # Overrides base WindowsCommon#FormatMessage
      def FormatMessage(flags, source, message_id, language_id, buffer, buffer_size, arguments)
        if source || arguments
          raise ::NotImplementedError, 'Not supporting FormatMessage source or arguments'
        end
        must_be_dword(message_id)
        must_be_dword(language_id)
        must_be_char_buffer(buffer, buffer_size)
        @format_message ||= ::Win32::API.new('FormatMessage', 'LLLLPLP', 'L', 'kernel32')
        @format_message.call(flags, API_NULL, message_id, language_id, buffer, buffer_size, API_NULL)
      end

      # Overrides base WindowsCommon#GetLastError
      def GetLastError
        @get_last_error ||= ::Win32::API.new('GetLastError', 'V', 'L', 'kernel32')
        @get_last_error.call
      end
    end  # WindowsCommon

    class WindowsSecurity

      # Overrides base WindowsSecurity#LookupPrivilegeValue
      def LookupPrivilegeValue(system_name, name, luid)
        must_be_string_or_nil(system_name)
        must_be_string(name)
        must_be_byte_buffer(luid, SIZEOF_QWORD)
        @lookup_privilege_value ||= ::Win32::API.new('LookupPrivilegeValue', 'PPP', 'B', 'advapi32')
        api_succeeded(
          @lookup_privilege_value.call(
            system_name ? system_name : API_NULL,
            name,
            luid))
      end

      # Overrides base WindowsSecurity#AdjustTokenPrivileges
      def AdjustTokenPrivileges(token_handle, disable_all_privileges, new_state, buffer_length, previous_state, return_length)
        must_be_dword(token_handle)
        must_be_bool(disable_all_privileges)
        must_be_buffer_or_nil(new_state)
        must_be_byte_buffer_or_nil(previous_state, buffer_length)
        must_be_byte_buffer_or_nil(return_length, return_length ? SIZEOF_DWORD : 0)
        @adjust_token_privileges ||= ::Win32::API.new('AdjustTokenPrivileges', 'LLPLPP', 'B', 'advapi32')
        api_succeeded(
          @adjust_token_privileges.call(
            token_handle,
            disable_all_privileges ? API_TRUE : API_FALSE,
            new_state ? new_state : API_NULL,
            buffer_length,
            previous_state ? previous_state : API_NULL,
            return_length ? return_length : API_NULL))
      end
    end  # WindowsSecurity

    class WindowsSystemInformation

      # Overrides base WindowsSystemInformation#GetVersionEx
      def GetVersionEx(version_info_buffer)
        must_be_size_prefixed_buffer(version_info_buffer)
        @get_version_ex ||= ::Win32::API.new('GetVersionEx', 'P', 'L', 'kernel32')
        api_succeeded(@get_version_ex.call(version_info_buffer))
      end

      # Overrides base WindowsSystemInformation#create_os_version_info
      def create_os_version_info
        [
          148,        #  0 - size of OSVERSIONINFO (IN)
          0,          #  4 - major version (OUT)
          0,          #  8 - minor version (OUT)
          0,          # 12 - build (OUT)
          0,          # 16 - platform (OUT)
          0.chr * 128 # 20 - additional info (OUT)
        ].pack('LLLLLa128')
      end

      # Overrides base WindowsSystemInformation#unpack_os_version_info
      def unpack_os_version_info(buffer)
        buffer.unpack('LLLLLZ128') # 'Z' means ASCIIZ string
      end
    end # WindowsSystemInformation

    private

    # Overrides base Platform#initialize_species
    def initialize_species
      true # do nothing
    end

  end # Platform

end # RightScale
