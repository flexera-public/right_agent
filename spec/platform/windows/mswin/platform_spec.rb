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

# stub out definition of ::Win32::API for testing on non-Windows platforms.
module Win32
  class API; end
end

describe RightScale::Platform do

  include PlatformSpecHelper

  context 'windows/mswin' do

    # required by before_all_platform_tests
    # called by before(:all) so not defined using let().
    def expected_genus; :windows; end
    def expected_species; :mswin; end

    def instrument_win32_error(error_code, error_message)
      w32a = flexmock(::Win32::API)
      w32a.
        should_receive(:new).
        with('GetLastError', 'V', 'L', 'kernel32').
        and_return(lambda { error_code }).
        once
      w32a.
        should_receive(:new).
        with('FormatMessage', 'LLLLPLP', 'L', 'kernel32').
        and_return do
          lambda do |flags, _, message_id, _, buffer, _, _|

            if flags == 0x1200 && message_id == 5
              error_message.chars.each_with_index do |c, index|
                buffer[index] = c
              end
              error_message.length
            else
              fail "Unexpected arguments: #{[mn, m, t, tac, ras].inspect}"
            end
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
        w32a = flexmock(::Win32::API)
        w32a.
          should_receive(:new).
          with('GetLastError', 'V', 'L', 'kernel32').
          and_return(lambda { 0 }).
          once
        w32a.
          should_receive(:new).
          with('GetVersionEx', 'P', 'L', 'kernel32').
          and_return(
            lambda do |vib|
              vib[4,12] = [major, minor, build].pack('LLL')
              1
            end
          ).once
      end

      it_should_behave_like 'supports windows platform initialization'
    end # initialization

    context :controller do
      subject { described_class.controller }

      def instrument_initiate_system_shutdown_api(reboot_after_shutdown)
        w32a = flexmock(::Win32::API)
        w32a.
          should_receive(:new).
          with('GetCurrentProcess', 'V', 'L', 'kernel32').
          and_return(lambda { -1 }).
          once
        w32a.
          should_receive(:new).
          with('OpenProcessToken', 'LLP', 'B', 'advapi32').
          and_return(lambda { |ph, da, th| 1 }).
          once
        w32a.
          should_receive(:new).
          with('LookupPrivilegeValue', 'PPP', 'B', 'advapi32').
          and_return(lambda { |sn, n, luid| 1 }).
          once
        w32a.
          should_receive(:new).
          with('AdjustTokenPrivileges', 'LLPLPP', 'B', 'advapi32').
          and_return(lambda { |th, dap, ns, bl, ps, rl| 1 }).
          once
        w32a.
          should_receive(:new).
          with('InitiateSystemShutdown', 'PPLLL', 'B', 'advapi32').
          and_return(
            lambda do |mn, m, t, tac, ras|
              if mn == 0 && m == 0 && t == 1 && tac == 1 && ras == (reboot_after_shutdown ? 1 : 0)
                1
              else
                fail "Unexpected arguments: #{[mn, m, t, tac, ras].inspect}"
              end
            end
          ).once
        w32a.
          should_receive(:new).
          with('CloseHandle', 'L', 'B', 'kernel32').
          and_return(lambda { |h| 1 }).
          once
      end

      it_should_behave_like 'supports windows platform controller'
    end # controller

    context :filesystem do
      subject { flexmock(described_class.filesystem) }

      def instrument_create_symbolic_link_api(from_path, to_path, flags, &callback)
        flexmock(::Win32::API).
          should_receive(:new).
          with('CreateSymbolicLink', 'SSL', 'B', 'kernel32').
          and_return(
            lambda do |tp, fp, fgs|
              if fp == (from_path + 0.chr) && tp == (to_path + 0.chr) && fgs == flags
                callback.call
              else
                fail "Unexpected arguments: #{[tp, fp, fgs].inspect}"
              end
            end
          ).once
      end

      def instrument_get_short_path_name_api(long_path, short_path_from_api, &callback)
        flexmock(::Win32::API).
          should_receive(:new).
          with('GetShortPathName', 'SPL', 'L', 'kernel32').
          and_return(
            lambda do |lp, short_path_buffer, short_path_buffer_length|
              if lp == (long_path + 0.chr)
                short_path_from_api.chars.each_with_index do |c, index|
                  short_path_buffer[index] = c
                end
                callback.call
              else
                fail "Unexpected arguments: #{lp.inspect}"
              end
            end
          ).once
      end

      def instrument_get_temp_path_api(temp_path_from_api, &callback)
        flexmock(::Win32::API).
          should_receive(:new).
          with('GetTempPath', 'LP', 'L', 'kernel32').
          and_return(
            lambda do |buffer_length, buffer|
              temp_path_from_api.chars.each_with_index do |c, index|
                buffer[index] = c
              end
              callback.call
            end
          ).once
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
        w32a = flexmock(::Win32::API)
        w32a.
          should_receive(:new).
          with('GetCurrentProcess', 'V', 'L', 'kernel32').
          and_return(lambda { -1 }).
          once
        w32a.
          should_receive(:new).
          with('GetProcessMemoryInfo', 'LPL', 'B', 'psapi').
          and_return(
            lambda do |ph, pmib, pmibs|
              pmib[3 * 4, 4] = [resident_set_size * 1024].pack('L')
              1
            end
          ).once
      end

      it_should_behave_like 'supports windows platform process'
    end # process

    context :volume_manager do
      subject { flexmock(described_class.volume_manager) }

      it_should_behave_like 'supports windows platform volume manager'
    end # volume_manager

  end # windows/mswin
end # RightScale::Platform
