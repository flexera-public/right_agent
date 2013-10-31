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

describe RightScale::Platform do
  include PlatformSpecHelper

  context 'unix/darwin' do

    # required by before_all_platform_tests
    # called by before(:all) so not defined using let().
    def expected_genus; :unix; end
    def expected_species; :darwin; end

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

    context 'statics' do
      subject { platform_class }

      it 'should be linux' do
        subject.unix?.should be_true
        subject.windows?.should be_false
        subject.linux?.should be_false
        subject.darwin?.should be_true
      end
    end

    context 'initialization' do

      let(:sw_vers_cmd) { 'sw_vers -productVersion 2>&1' }

      context 'when sw_vers is available' do
        it 'should initialize from sw_vers data' do
          platform_instance.
            should_receive(:execute).
            with(sw_vers_cmd).
            and_return("10.8.5\n").
            once
          platform_instance.send(:initialize_species)
          platform_instance.flavor.should == 'mac_os_x'
          platform_instance.release.should == '10.8.5'
          platform_instance.codename.should == ''
        end
      end # when lsb_release is available

      context 'when sw_vers is not available' do
        it 'should be unknown release' do
          platform_instance.
            should_receive(:execute).
            with(sw_vers_cmd).
            and_raise(described_class::CommandError).
            once
          platform_instance.send(:initialize_species)
          platform_instance.flavor.should == 'mac_os_x'
          platform_instance.release.should == 'unknown'
          platform_instance.codename.should == 'unknown'
        end
      end # when lsb_release is not available
    end # initialization

    context :controller do
      subject { described_class.controller }

      context '#reboot' do
        it 'should call shutdown -r now under darwin' do
          platform_class.should_receive(:execute).with('shutdown -r now 2>&1', {}).and_return('')
          subject.reboot.should be_true
        end
      end # reboot

      context '#shutdown' do
        it 'should call shutdown -h now under darwin' do
          platform_class.should_receive(:execute).with('shutdown -h now 2>&1', {}).and_return('')
          subject.shutdown.should be_true
        end
      end # shutdown
    end # controller

    context :filesystem do
      subject { described_class.filesystem }

      it_should_behave_like 'supports unix platform filesystem'
    end

    context :installer do
      subject { described_class.installer }

      context :install do
        it 'should raise not implemented' do
          expect { subject.install(%w[foo bar]) }.
           to raise_error(
             ::NotImplementedError, 'Not yet supporting Mac OS package install')
        end
      end # install
    end # installer

    context :shell do
      subject { described_class.shell }

      # required by 'supports any platform shell'
      def instrument_booted_at(booted_at)
        time = ::Time.at(booted_at.to_i)
        platform_class.
          should_receive(:execute).
          with('sysctl kern.boottime', {}).
          and_return("kern.boottime: { sec = #{time.to_i}, usec = 0 } #{time.to_s}")

        # note that uptime is computed relative to boottime.
        true
      end

      it_should_behave_like 'supports unix platform shell'
    end

    context :rng do
      subject { described_class.rng }

      it_should_behave_like 'supports unix platform rng'
    end

    context :process do
      subject { described_class.process }

      it_should_behave_like 'supports unix platform process'
    end

    context :volume_manager do
      subject { platform_class.volume_manager }

      context :volumes do
        it 'should raise not implemented' do
          expect { subject.volumes }.
            to raise_error(
             ::NotImplementedError, 'Not yet supporting Mac OS volume query')
        end
      end # volumes

      context :mount_volume do
        it 'should raise not implemented' do
          expect { subject.volumes }.
            to raise_error(
             ::NotImplementedError, 'Not yet supporting Mac OS volume query')
        end
      end # mount_volume
    end # volume_manager
  end # under unix/darwin
end # RightScale::Platform
