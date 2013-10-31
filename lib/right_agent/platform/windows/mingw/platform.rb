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

require ::File.expand_path('../../../../platform', __FILE__)

# ignore unless Windows as a concession to spec testing from non-Windows.
# any windows-only gems must be fully mocked under test.
if RUBY_PLATFORM =~ /mingw/
  # Foreign Function Interface used for all API calls in mingw
  require 'ffi'
end

module RightScale

  # Windows specific implementation
  class Platform

    # helpers
    class PlatformHelperBase
      # _W (i.e. 'wide') Windows APIs all use little-endian unicode.
      #
      # _A doesn't correspond to any particular single/multi-byte encoding (even
      # though n00bs get confused and think in means ASCII). _A actually means
      # 'use the current codepage' for which you would need to make another API
      # call to discover what the current thread thinks is the current codepage.
      WIDE = ::Encoding::UTF_16LE

      # We favor the _W APIs to ensure proper marshalling of Unicode characters
      # to/from the ruby interpreter's default codepage. This method facilitates
      # API calls that fill a Unicode buffer and need to marshal the buffered
      # data to a multi-byte (default encoding) buffer.
      #
      # @param [String] buffer to receive marshalled data from Unicode API or
      #   nil to query required buffer.
      # @param [Hash] copy_options for copy_to_string_buffer
      #
      # @yield [buffer] yields the buffer at current size for API call
      # @yieldparam [String] buffer to use for API call (get size from buffer)
      #  or nil to query required buffer size.
      #
      # @return [String] buffered data length or zero for failure
      def with_unicode_buffer(buffer, copy_options = {})
        # note that _W methods always expect UTF-16 LE (Little Endian) due to
        # the Intel chipset representing word values as LE. Windows runs on
        # other chipsets but LE is always used by API calls.
        if buffer && buffer.encoding != WIDE
          unicode_buffer = 0.chr.encode(WIDE) * buffer.size
          unicode_length_or_buffer_count = yield(unicode_buffer)

          if unicode_length_or_buffer_count > 0 &&
             unicode_length_or_buffer_count < unicode_buffer.size

            # reencode to non-Unicode buffer, including trailing NUL character.
            #
            # note that reencoding may exceed given (Unicode) buffer size
            # because of two-byte chars expanded from single unicode chars.
            # in this case the required multi-byte buffer size will be returned
            # and then promoted to a 'doubled' Unicode buffer size on next call.
            result = copy_to_string_buffer(
              unicode_buffer[0, unicode_length_or_buffer_count + 1],
              buffer,
              copy_options)
          else
            result = unicode_length_or_buffer_count
          end
        else
          # buffer is already UTF-16LE or else nil
          result = yield(buffer)
        end
        result
      end

      # Performs a bytewise copy to given target buffer with respect for the
      # encoding of the source and target buffers. Assumes a NUL terminator
      # appears in the string to be copied per normal Windows API behavor.
      #
      # @param [String] source_buffer encoded source
      # @param [String] target_buffer encoded target
      # @param [Hash] options for copy
      # @option options [TrueClass|FalseClass] :truncate is true to allow
      #   trunction of string to fit buffer, false to return required buffer
      #   size if copy would exceed buffer
      #
      # @return [Integer] length of encoded target or else buffer length needed for full copy
      def copy_to_string_buffer(source_buffer, target_buffer, options = {})
        options = { :truncate => false }.merge(options)

        # note that a buffer of NULs will default to ASCII encoding in
        # ruby 1.9 so change to use default encoding automagically. this makes
        # it easier to support the default codepage in 1.9 but be oblivious to
        # it in 1.8, which does not support these encoding methods. if the
        # caller wants any other codepage (in 1.9) then it should be specified
        # on the target.
        if target_buffer.encoding == Encoding::ASCII
          # we can force encoding only if the default encoding is ASCII
          # compatible. we are going to clobber the bytes so the old bytes are
          # irrelevant unless the bytesize of the buffer would differ.
          if ::Encoding.default_external.ascii_compatible?
            # note that force_encoding modifies self even though it's not a
            # banged! method.
            target_buffer.force_encoding(::Encoding.default_external)
          else
            target_buffer.encode!(::Encoding.default_external)
          end
        end

        # reencode the source buffer, changing any characters that cannot be
        # encoded to the default replacement character, which is usually '?'
        target_encoding = target_buffer.encoding
        reencoded_source_buffer = source_buffer.encode(
          target_encoding, :invalid => :replace, :undef => :replace)

        # determine if sufficient buffer exists.
        result = nil
        nul_char = 0.chr.encode(target_encoding)
        reencoded_source_length = reencoded_source_buffer.index(nul_char) ||
          reencoded_source_buffer.length
        if reencoded_source_length <= target_buffer.length || options[:truncate]
          # bytewise replacement (to reuse caller's buffer instead of
          # reallocating the string's buffer).
          copy_length = [reencoded_source_length, target_buffer.length - 1].min
          copy_byte_count = nul_char.bytesize * copy_length
          reencoded_source_buffer.bytes.each_with_index do |b, b_index|
            break if b_index >= copy_byte_count
            target_buffer.setbyte(b_index, b)
          end
          target_buffer[copy_length] = nul_char
          result = copy_length
        else
          result = reencoded_source_length
        end
        result
      end
    end

    class Filesystem

      # FFI APIs
      class API
        extend FFI::Library

        typedef :ulong, :dword

        ffi_lib :kernel32

        # the FFI wiki documents that it is important to specify the stdcall
        # calling convention properly, but public gems like win32-dir don't
        # bother; who do you believe?
        #
        # @see https://github.com/ffi/ffi/wiki/Windows-Examples
        #
        # looking at the FFI assembly code, it may workaround a gem using the
        # wrong calling convention by always restoring the stack pointer after
        # the call, but that's no excuse to call things improperly.
        ffi_convention :stdcall

        # yes, we could import the _A APIs but what codepage would they use?
        # it's better not to think about it and do the extra marshalling for _W,
        # which is always Encoding::UTF_16LE. the reality of WinNT+ is that it
        # implements all APIs as _W and does extra marshalling with a lookup to
        # the thread's current codepage on every call to an _A API.
        attach_function :GetShortPathNameW, [:buffer_in, :buffer_out, :dword], :dword
        attach_function :GetTempPathW, [:dword, :buffer_out], :dword

        begin
          attach_function :CreateSymbolicLinkW, [:buffer_in, :buffer_in, :dword], :bool
        rescue FFI::NotFoundError
          # we don't really support 2003 server any longer but ignore this.
        end
      end

      # Overrides base Filesystem#CreateSymbolicLink
      def CreateSymbolicLink(symlink_file_path, target_file_path, flags)
        must_be_string(symlink_file_path)
        must_be_string(target_file_path)
        must_be_dword(flags)
        if defined?(API.CreateSymbolicLinkW)
          API.CreateSymbolicLinkW(
            symlink_file_path.encode(WIDE),
            target_file_path.encode(WIDE),
            flags)
        else
          raise ::RightScale::Exceptions::PlatformError,
                'Cannot create symlinks on this platform'
        end
      end

      # Overrides base Filesystem#GetShortPathName
      def GetShortPathName(long_path, short_path_buffer, short_path_buffer_length)
        must_be_string(long_path)
        must_be_char_buffer_or_nil(short_path_buffer, short_path_buffer_length)
        with_unicode_buffer(short_path_buffer) do |unicode_buffer|
          API.GetShortPathNameW(
            long_path.encode(WIDE),
            unicode_buffer,
            unicode_buffer ? unicode_buffer.size : 0)
        end
      end

      # Overrides base Filesystem#GetTempDir
      def GetTempPath(buffer_length, buffer)
        must_be_char_buffer_or_nil(buffer, buffer_length)
        with_unicode_buffer(buffer) do |unicode_buffer|
          API.GetTempPathW(
            unicode_buffer ? unicode_buffer.size : 0,
            unicode_buffer)
        end
      end
    end # Filesystem

    class Controller

      # FFI APIs
      class API
        extend FFI::Library

        typedef :ulong, :dword

        ffi_lib :advapi32
        ffi_convention :stdcall

        attach_function :InitiateSystemShutdownW, [:buffer_in, :buffer_in, :dword, :bool, :bool], :bool
      end

      # Overrides base Controller#InitiateSystemShutdown
      def InitiateSystemShutdown(machine_name, message, timeout, force_apps_closed, reboot_after_shutdown)
        must_be_string_or_nil(machine_name)
        must_be_string_or_nil(message)
        must_be_dword(timeout)
        must_be_bool(force_apps_closed)
        must_be_bool(reboot_after_shutdown)
        API.InitiateSystemShutdownW(
          machine_name ? machine_name.encode(WIDE) : nil,
          message ? message.encode(WIDE) : nil,
          timeout,
          force_apps_closed,
          reboot_after_shutdown)
      end
    end # Controller

    class Process

      # FFI APIs
      class API
        extend FFI::Library

        typedef :uintptr_t, :handle
        typedef :ulong, :dword

        ffi_lib :kernel32
        ffi_convention :stdcall

        attach_function :GetCurrentProcess, [], :handle

        ffi_lib :psapi
        ffi_convention :stdcall

        attach_function :GetProcessMemoryInfo, [:handle, :buffer_out, :dword], :bool

        ffi_lib :advapi32
        ffi_convention :stdcall

        attach_function :OpenProcessToken, [:handle, :dword, :buffer_out], :bool
      end

      # Overrides base Process#GetCurrentProcess
      def GetCurrentProcess
        API.GetCurrentProcess
      end

      # Overrides base Process#GetProcessMemoryInfo
      def GetProcessMemoryInfo(process_handle, process_memory_info_buffer, process_memory_info_buffer_size)
        must_be_dword(process_handle)
        must_be_size_prefixed_buffer(process_memory_info_buffer, process_memory_info_buffer_size)
        API.GetProcessMemoryInfo(
          process_handle,
          process_memory_info_buffer,
          process_memory_info_buffer_size)
      end

      # Overrides base Process#OpenProcessToken
      def OpenProcessToken(process_handle, desired_access, token_handle)
        must_be_dword(process_handle)
        must_be_dword(desired_access)
        must_be_byte_buffer(token_handle, SIZEOF_DWORD)
        API.OpenProcessToken(process_handle, desired_access, token_handle)
      end
    end  # Process

    class WindowsCommon

      # FFI APIs
      class API
        extend FFI::Library

        typedef :uintptr_t, :handle
        typedef :ulong, :dword

        ffi_lib :kernel32
        ffi_convention :stdcall

        attach_function :CloseHandle, [:handle], :bool
        attach_function :FormatMessageW, [:dword, :buffer_in, :dword, :dword, :buffer_out, :dword, :buffer_in], :dword
      end

      # Overrides base WindowsCommon#CloseHandle
      def CloseHandle(handle)
        must_be_dword(handle)
        API.CloseHandle(handle)
      end

      # Overrides base WindowsCommon#FormatMessage
      def FormatMessage(flags, source, message_id, language_id, buffer, buffer_size, arguments)
        unless source.nil? && arguments.nil?
          raise ::NotImplementedError,
                'Not supporting FormatMessage source or arguments'
        end
        must_be_dword(message_id)
        must_be_dword(language_id)
        must_be_char_buffer(buffer, buffer_size)
        with_unicode_buffer(buffer, :truncate => true) do |unicode_buffer|
          API.FormatMessageW(
            flags, source, message_id, language_id,
            unicode_buffer, unicode_buffer.size, arguments)
        end
      end

      # Overrides base WindowsCommon#GetLastError
      def GetLastError
        # note that you cannot call GetLastError API via FFI without changing
        # the last error code; Heisenberg Uncertainty API. the documented
        # workaround is to call the following method.
        ::FFI::errno
      end
    end  # WindowsCommon

    class WindowsSecurity

      # FFI APIs
      class API
        extend FFI::Library

        typedef :uintptr_t, :handle
        typedef :ulong, :dword

        ffi_lib :advapi32
        ffi_convention :stdcall

        attach_function :LookupPrivilegeValueW, [:buffer_in, :buffer_in, :pointer], :bool
        attach_function :AdjustTokenPrivileges, [:handle, :bool, :buffer_in, :dword, :buffer_out, :buffer_out], :bool
      end

      # Overrides base WindowsSecurity#LookupPrivilegeValue
      def LookupPrivilegeValue(system_name, name, luid)
        must_be_string_or_nil(system_name)
        must_be_string(name)
        must_be_byte_buffer(luid, SIZEOF_QWORD)
        API.LookupPrivilegeValueW(
          system_name ? system_name.encode(WIDE) : nil,
          name.encode(WIDE),
          luid)
      end

      # Overrides base WindowsSecurity#AdjustTokenPrivileges
      def AdjustTokenPrivileges(token_handle, disable_all_privileges, new_state, buffer_length, previous_state, return_length)
        must_be_dword(token_handle)
        must_be_bool(disable_all_privileges)
        must_be_buffer_or_nil(new_state)
        must_be_byte_buffer_or_nil(previous_state, buffer_length)
        must_be_byte_buffer_or_nil(return_length, return_length ? SIZEOF_DWORD : 0)
        API.AdjustTokenPrivileges(
          token_handle, disable_all_privileges, new_state,
          buffer_length, previous_state, return_length)
      end
    end  # WindowsSecurity

    class WindowsSystemInformation

      # FFI APIs
      class API
        extend FFI::Library

        typedef :ulong, :dword

        ffi_lib :kernel32
        ffi_convention :stdcall

        attach_function :GetVersionExW, [:buffer_out], :bool
      end

      # Overrides base WindowsSystemInformation#GetVersionEx
      def GetVersionEx(version_info_buffer)
        must_be_size_prefixed_buffer(version_info_buffer)
        API.GetVersionExW(version_info_buffer)
      end

      # Overrides base WindowsSystemInformation#create_os_version_info
      def create_os_version_info
        [
          276,            #  0 - size of OSVERSIONINFO (IN)
          0,              #  4 - major version (OUT)
          0,              #  8 - minor version (OUT)
          0,              # 12 - build (OUT)
          0,              # 16 - platform (OUT)
          0.chr * 128 * 2 # 20 - additional info (OUT)
        ].pack('LLLLLa256')
      end

      # Overrides base WindowsSystemInformation#unpack_os_version_info
      def unpack_os_version_info(buffer)
        result = buffer.unpack('LLLLL')
        additional_info = buffer[20, 256].force_encoding(WIDE)
        additional_info_length = additional_info.index(0.chr.encode(additional_info.encoding)) || additional_info.length
        result << additional_info[0, additional_info_length].encode(::Encoding.default_external)
        result
      end
    end # WindowsSystemInformation

    private

    # Overrides base Platform#initialize_species
    def initialize_species
      true # do nothing
    end

  end # Platform

end # RightScale
