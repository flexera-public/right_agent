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

require ::File.expand_path('../../spec_helper', __FILE__)

# stub FII for testing on non-mingw platforms; any mingw-specific tests must
# mock API calls.
module FFI
  module Library

    def typedef(*args)
      true
    end

    def ffi_lib(*args)
      true
    end

    def ffi_convention(*args)
      true
    end

    def attach_function(*args)
      true
    end
  end
end

describe RightScale::Platform do

  include PlatformSpecHelper

  context 'windows/mingw' do

    # required by before_all_platform_tests
    # called by before(:all) so not defined using let().
    def expected_genus; :windows; end
    def expected_species; :mingw; end

    def to_wide(str)
      str.encode(::RightScale::Platform::PlatformHelperBase::WIDE)
    end

    def instrument_win32_error(error_code, error_message)
      flexmock(::FFI).should_receive(:errno).and_return(error_code).once
      flexmock(described_class::WindowsCommon::API).
        should_receive(:FormatMessageW).
        with(0x1200, nil, error_code, 0, String, Integer, nil).
        and_return do |flags, _, message_id, _, unicode_buffer, _, _|
          if flags == 0x1200 && message_id == 5
            unicode_message = to_wide(error_message)
            unicode_message.chars.each_with_index do |c, index|
              unicode_buffer[index] = c
            end
            unicode_message.length
          else
            fail "Unexpected arguments: #{[flags, message_id].inspect}"
          end
        end.once
    end

    before(:all) do
      before_all_platform_tests
    end

    after(:all) do
      after_all_platform_tests
    end

    before(:each) do
      before_each_platform_test
    end

    after(:each) do
      after_each_platform_test
    end

    context :statics do
      subject { platform_class }

      it_should_behave_like 'supports windows platform statics'
    end

    context :initialization do
      def instrument_os_info(major, minor, build)
        flexmock(::FFI).should_receive(:errno).and_return(0).once
        flexmock(described_class::WindowsSystemInformation::API).
          should_receive(:GetVersionExW).
          with(String).
          and_return do |vib|
            vib[4,12] = [major, minor, build].pack('LLL')
          end.once
      end

      it_should_behave_like 'supports windows platform initialization'
    end # initialization

    context :controller do
      subject { described_class.controller }

      def instrument_initiate_system_shutdown_api(reboot_after_shutdown)
        controller_api = flexmock(described_class::Controller::API)
        process_api = flexmock(described_class::Process::API)
        windows_common_api = flexmock(described_class::WindowsCommon::API)
        windows_security_api = flexmock(described_class::WindowsSecurity::API)

        process_api.should_receive(:GetCurrentProcess).and_return(-1).once
        process_api.should_receive(:OpenProcessToken).and_return(true).once
        windows_security_api.should_receive(:LookupPrivilegeValueW).and_return(true).once
        windows_security_api.should_receive(:AdjustTokenPrivileges).and_return(true).once
        controller_api.
          should_receive(:InitiateSystemShutdownW).
          with(nil, nil, 1, true, reboot_after_shutdown).
          and_return(true).
          once
        windows_common_api.should_receive(:CloseHandle).and_return(true).once
      end

      it_should_behave_like 'supports windows platform controller'
    end # controller

    context :filesystem do
      subject { flexmock(described_class.filesystem) }

      def instrument_create_symbolic_link_api(from_path, to_path, flags, &callback)
        flexmock(described_class::Filesystem::API).
          should_receive(:CreateSymbolicLinkW).
          with(to_wide(to_path + 0.chr), to_wide(from_path + 0.chr), flags).
          and_return { callback.call == 0 ? false : true }.
          once
      end

      def instrument_get_short_path_name_api(long_path, short_path_from_api, &callback)
        flexmock(described_class::Filesystem::API).
          should_receive(:GetShortPathNameW).
          with(to_wide(long_path + 0.chr), String, Integer).
          and_return do |lp, short_path_buffer, _|
            to_wide(short_path_from_api).chars.each_with_index do |c, index|
              short_path_buffer[index] = c
            end
            callback.call
          end.once
      end

      def instrument_get_temp_path_api(temp_path_from_api, &callback)
        flexmock(described_class::Filesystem::API).
          should_receive(:GetTempPathW).
          with(Integer, String).
          and_return do |_, buffer|
            to_wide(temp_path_from_api).chars.each_with_index do |c, index|
              buffer[index] = c
            end
            callback.call
          end.once
      end

      it_should_behave_like 'supports windows platform filesystem'
    end # filesystem

    context :installer do
      subject { described_class.installer }

      it_should_behave_like 'supports windows platform installer'
    end # installer

    context :shell do
      subject { flexmock(described_class.shell) }

      it_should_behave_like 'supports windows platform shell'
    end # shell

    context :rng do
      subject { described_class.rng }

      it_should_behave_like 'supports windows platform rng'
    end # rng

    context :process do
      subject { described_class.process }

      def instrument_get_process_memory_info_api(resident_set_size)
        process_api = flexmock(described_class::Process::API)
        process_api.should_receive(:GetCurrentProcess).and_return(-1).once
        process_api.
          should_receive(:GetProcessMemoryInfo).
          with(-1, String, Integer).
          and_return do |_, pmib, _|
            pmib[3 * 4, 4] = [resident_set_size * 1024].pack('L')
            true
          end.once
      end

      it_should_behave_like 'supports windows platform process'
    end # process

    context :volume_manager do
      subject { flexmock(described_class.volume_manager) }

      it_should_behave_like 'supports windows platform volume manager'
    end # volume_manager

  end # windows/mingw
end # RightScale::Platform
