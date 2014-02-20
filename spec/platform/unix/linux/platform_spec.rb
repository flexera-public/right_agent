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

  context 'unix/linux' do

    # required by before_all_platform_tests
    # called by before(:all) so not defined using let().
    def expected_genus; :unix; end
    def expected_species; :linux; end

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
        subject.linux?.should be_true
        subject.darwin?.should be_false
      end
    end

    context 'initialization' do
      let(:lsb_help_cmd) { 'lsb_release --help >/dev/null 2>&1' }

      context 'when lsb_release is available' do
        it 'should initialize from lsb_release data' do
          platform_instance.
            should_receive(:execute).
            with(lsb_help_cmd).
            and_return("lsb_release\nhelp\ndump\n").
            once
          platform_instance.
            should_receive(:execute).
            with('lsb_release -is', { :raise_on_failure => false }).
            and_return("Ubuntu\n").
            once
          platform_instance.
            should_receive(:execute).
            with('lsb_release -rs', { :raise_on_failure => false }).
            and_return("11.04\n").
            once
          platform_instance.
            should_receive(:execute).
            with('lsb_release -cs', { :raise_on_failure => false }).
            and_return("natty\n").
            once
          platform_instance.send(:initialize_species)
          platform_instance.flavor.should == 'ubuntu'
          platform_instance.release.should == '11.04'
          platform_instance.codename.should == 'natty'
          platform_instance.ubuntu?.should be_true
          platform_instance.centos?.should be_false
          platform_instance.suse?.should be_false
          platform_instance.rhel?.should be_false
        end
      end # when lsb_release is available

      context 'when lsb_release is not available' do
        before(:each) do
          platform_instance.
            should_receive(:execute).
            with(lsb_help_cmd).
            and_raise(described_class::CommandError).
            once
        end

        context 'when fedora release is available' do
          it 'should be fedora' do
            file_mock = flexmock(::File)
            file_mock.
              should_receive(:exist?).
              with(described_class::FEDORA_REL).
              and_return(true).
              once
            file_mock.
              should_receive(:read).
              with(described_class::FEDORA_REL).
              and_return("Fedora release 7 (Moonshine)\n").
              once
            platform_instance.send(:initialize_species)
            platform_instance.flavor.should == 'fedora'
            platform_instance.release.should == '7'
            platform_instance.codename.should == 'Moonshine'
            platform_instance.ubuntu?.should be_false
            platform_instance.centos?.should be_false
            platform_instance.suse?.should be_false
            platform_instance.rhel?.should be_false
          end
        end # when fedora release is available

        context 'when fedora release is not available' do
          it 'should be unknown' do
            file_mock = flexmock(::File)
            file_mock.
              should_receive(:exist?).
              with(described_class::FEDORA_REL).
              and_return(false).
              once
            platform_instance.send(:initialize_species)
            platform_instance.flavor.should == 'unknown'
            platform_instance.release.should == 'unknown'
            platform_instance.codename.should == 'unknown'
            platform_instance.ubuntu?.should be_false
            platform_instance.centos?.should be_false
            platform_instance.suse?.should be_false
            platform_instance.rhel?.should be_false
          end
        end # when fedora release is not available
      end # when lsb_release is not available
    end # initialization

    context :controller do
      subject { described_class.controller }

      context '#reboot' do
        it 'should call init 6 under unix' do
          platform_class.should_receive(:execute).with('reboot -f 2>&1', {}).and_return('')
          subject.reboot.should be_true
        end
      end # reboot

      context '#shutdown' do
        it 'should call init 0 under unix' do
          platform_class.should_receive(:execute).with('init 0 2>&1', {}).and_return('')
          subject.shutdown.should be_true
        end
      end # shutdown
    end # controller

    context :filesystem do
      subject { described_class.filesystem }

      it_should_behave_like 'supports unix platform filesystem'
    end

    context :installer do
      subject { installer = described_class.installer; flexmock(installer) }

      context :install do
        let(:packages) { %w[foo bar] }

        let(:installer_data) do
          {
            :aptitude => {
              :command => "apt-get install -y #{packages.join(' ')} 2>&1",
              :failure => "E: Couldn't find package #{packages.last}"
            },
            :yum => {
              :command => "yum install -y #{packages.join(' ')} 2>&1",
              :failure => "No package #{packages.last} available."
            },
            :zypper => {
              :command => "zypper --no-gpg-checks -n #{packages.join(' ')} 2>&1",
              :failure => "Package '#{packages.last}' not found."
            }
          }
        end

        before(:each) do
          installer_data.keys.each do |installer_kind|
            quiz = (installer_kind.to_s + '?').to_sym
            subject.should_receive(quiz).and_return do
              installer_kind == expected_installer_kind
            end
          end
        end

        shared_examples_for 'supports linux platform installer install' do
          it 'should succeed if no packages are specified' do
            subject.install([]).should == true
          end

          it 'should succeed if all packages install successfully' do
            platform_class.
              should_receive(:execute).
              with(installer_data[expected_installer_kind][:command], {}).
              and_return('ok')
            subject.install(packages).should == true
          end

          it 'should fail if one more packages are not found' do
            platform_class.
            should_receive(:execute).
              with(installer_data[expected_installer_kind][:command], {}).
              and_return(installer_data[expected_installer_kind][:failure])
            expect { subject.install(packages) }.
              to raise_error(
                described_class::Installer::PackageNotFound,
                'The following packages were not available: bar')
          end
        end

        [:aptitude, :yum, :zypper].each do |eik|
          context eik do
            let(:expected_installer_kind) { eik }

            it_should_behave_like 'supports linux platform installer install'
          end
        end

        context 'given no installers' do
          let(:expected_installer_kind) { nil }

          it 'should fail if no installers are found' do
            expect { subject.install(packages) }.
             to raise_error(
               described_class::Installer::PackageManagerNotFound,
               'No package manager binary (apt, yum, zypper) found in /usr/bin')
          end
        end
      end # install
    end # installer

    context :shell do
      subject { described_class.shell }

      # required by 'supports any platform shell'
      def instrument_booted_at(booted_at)
        mock_file = flexmock(::File)
        mock_file.should_receive(:read).with('/proc/stat').and_return(
<<EOF
...
ctxt 234567
btime #{booted_at.to_i}
processes 2345
...
EOF
        )
        mock_file.should_receive(:read).with('/proc/uptime').and_return do
          uptime = yield
          "#{uptime.to_f} #{0.99 * uptime.to_f}"
        end
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
      let(:blkid_cmd) { 'blkid 2>&1' }

      subject { platform_class.volume_manager }

      context :volumes do
        it 'can parse volumes from blkid output' do
          expected_volumes = [
            {
              :device     => '/dev/xvdh1',
              :sec_type   => 'msdos',
              :label      => 'METADATA',
              :uuid       => '681B-8C5D',
              :type       => 'vfat',
              :filesystem => 'vfat'
            },
            {
              :device     => '/dev/xvdb1',
              :label      => 'SWAP-xvdb1',
              :uuid       => 'd51fcca0-6b10-4934-a572-f3898dfd8840',
              :type       => 'swap',
              :filesystem => 'swap'
            },
            {
              :device     => '/dev/xvda1',
              :uuid       => 'f4746f9c-0557-4406-9267-5e918e87ca2e',
              :type       => 'ext3',
              :filesystem => 'ext3'
            },
            {
              :device     => '/dev/xvda2',
              :uuid       => '14d88b9e-9fe6-4974-a8d6-180acdae4016',
              :type       => 'ext3',
              :filesystem => 'ext3'
            }
          ]
          platform_class.should_receive(:execute).with(blkid_cmd, {}).and_return(
<<EOF
/dev/xvdh1: SEC_TYPE="msdos" LABEL="METADATA" UUID="681B-8C5D" TYPE="vfat"
/dev/xvdb1: LABEL="SWAP-xvdb1" UUID="d51fcca0-6b10-4934-a572-f3898dfd8840" TYPE="swap"
/dev/xvda1: UUID="f4746f9c-0557-4406-9267-5e918e87ca2e" TYPE="ext3"
/dev/xvda2: UUID="14d88b9e-9fe6-4974-a8d6-180acdae4016" TYPE="ext3"
EOF
          ).once
          subject.volumes.should == expected_volumes
        end

        it 'can parse volumes with hyphens or underscores (lvm use case)' do
          expected_volumes = [
            {
              :device     => '/dev/vg-rightscale-data_storage1/lvol0',
              :uuid       => 'ee34706d-866f-476e-9da4-6a18745456a4',
              :type       => 'xfs',
              :filesystem => 'xfs'
            }
          ]
          platform_class.should_receive(:execute).with(blkid_cmd, {}).and_return(
<<EOF
/dev/vg-rightscale-data_storage1/lvol0: UUID="ee34706d-866f-476e-9da4-6a18745456a4" TYPE="xfs"
EOF
          ).once
          subject.volumes.should == expected_volumes
        end

        it 'can parse volumes with periods' do
          expected_volumes = [
            {
              :device     => '/dev/please.dont.do.this',
              :uuid       => 'ee34706d-866f-476e-9da4-6a18745456a4',
              :type       => 'xfs',
              :filesystem => 'xfs'
            }
          ]
          platform_class.should_receive(:execute).with(blkid_cmd, {}).and_return(
<<EOF
/dev/please.dont.do.this: UUID="ee34706d-866f-476e-9da4-6a18745456a4" TYPE="xfs"
EOF
          ).once
          subject.volumes.should == expected_volumes
        end

        it 'raises a parser error when blkid output is malformed' do
          platform_class.should_receive(:execute).with(blkid_cmd, {}).and_return('gibberish').once
          expect { subject.volumes }.
            to raise_error(described_class::VolumeManager::ParserError)
        end

        it 'returns an empty list of volumes when blkid output is empty' do
          platform_class.should_receive(:execute).with(blkid_cmd, {}).and_return('').once
          subject.volumes.should == []
        end

        it 'can filter results with single condition and single match' do
          expected_volumes = [
            {
              :device     => '/dev/xvdh1',
              :sec_type   => 'msdos',
              :label      => 'METADATA',
              :uuid       => '681B-8C5D',
              :type       => 'vfat',
              :filesystem => 'vfat'
            }
          ]
          platform_class.should_receive(:execute).with(blkid_cmd, {}).and_return(
<<EOF
/dev/xvdh1: SEC_TYPE="msdos" LABEL="METADATA" UUID="681B-8C5D" TYPE="vfat"
/dev/xvdb1: LABEL="SWAP-xvdb1" UUID="d51fcca0-6b10-4934-a572-f3898dfd8840" TYPE="swap"
/dev/xvda1: UUID="f4746f9c-0557-4406-9267-5e918e87ca2e" TYPE="ext3"
/dev/xvda2: UUID="14d88b9e-9fe6-4974-a8d6-180acdae4016" TYPE="ext3"
EOF
          ).once
          subject.volumes(:uuid => expected_volumes[0][:uuid]).should == expected_volumes
        end

        it 'can filter results with multiple matches' do
          expected_volumes = [
            {
              :device     => '/dev/xvda1',
              :uuid       => 'f4746f9c-0557-4406-9267-5e918e87ca2e',
              :type       => 'ext3',
              :filesystem => 'ext3'
            },
            {
              :device     => '/dev/xvda2',
              :uuid       => '14d88b9e-9fe6-4974-a8d6-180acdae4016',
              :type       => 'ext3',
              :filesystem => 'ext3'
            }
          ]
          platform_class.should_receive(:execute).with(blkid_cmd, {}).and_return(
<<EOF
/dev/xvdh1: SEC_TYPE="msdos" LABEL="METADATA" UUID="681B-8C5D" TYPE="vfat"
/dev/xvdb1: LABEL="SWAP-xvdb1" UUID="d51fcca0-6b10-4934-a572-f3898dfd8840" TYPE="swap"
/dev/xvda1: UUID="f4746f9c-0557-4406-9267-5e918e87ca2e" TYPE="ext3"
/dev/xvda2: UUID="14d88b9e-9fe6-4974-a8d6-180acdae4016" TYPE="ext3"
EOF
          ).once
          subject.volumes(:filesystem => 'ext3', :type => 'ext3').should == expected_volumes
        end
      end

      context :mount_volume do
        it 'mounts the specified volume if it is not already mounted' do
          platform_class.
            should_receive(:execute).
            with('mount 2>&1', {}).
            and_return(
<<EOF
/dev/xvda2 on / type ext3 (rw,noatime,errors=remount-ro)
proc on /proc type proc (rw,noexec,nosuid,nodev)
EOF
)
          platform_class.
            should_receive(:execute).
            with('mount -t vfat /dev/xvdh1 /var/spool/softlayer 2>&1', {}).
            and_return('')
          subject.mount_volume(
            { :device => '/dev/xvdh1', :filesystem => 'vfat' },
            '/var/spool/softlayer')
        end

        it 'does not attempt to re-mount the volume' do
          platform_class.
            should_receive(:execute).
            with('mount 2>&1', {}).
            and_return(
<<EOF
/dev/xvda2 on / type ext3 (rw,noatime,errors=remount-ro)
proc on /proc type proc (rw,noexec,nosuid,nodev)
/dev/xvdh1 on /var/spool/softlayer type vfat (rw) [METADATA]
EOF
)
          platform_class.
            should_receive(:execute).
            with('mount -t vfat /dev/xvdh1 /var/spool/softlayer 2>&1', {}).
            and_return('')
          subject.mount_volume(
            {:device => '/dev/xvdh1', :filesystem => 'vfat'},
            '/var/spool/softlayer')
        end

        it 'raises argument error when the volume parameter is not a hash' do
          expect { subject.mount_volume('', '') }.
            to raise_error(ArgumentError)
        end

        it 'raises argument error when the volume parameter is a hash but does not contain :device' do
          expect { subject.mount_volume({}, '') }.
            to raise_error(ArgumentError)
        end

        it 'raises volume error when the device is already mounted to a different mountpoint' do
          platform_class.
            should_receive(:execute).
            with('mount 2>&1', {}).
            and_return(
<<EOF
/dev/xvda2 on / type ext3 (rw,noatime,errors=remount-ro)
proc on /proc type proc (rw,noexec,nosuid,nodev)
none on /sys type sysfs (rw,noexec,nosuid,nodev)
none on /sys/kernel/debug type debugfs (rw)
none on /sys/kernel/security type securityfs (rw)
none on /dev type devtmpfs (rw,mode=0755)
none on /dev/pts type devpts (rw,noexec,nosuid,gid=5,mode=0620)
none on /dev/shm type tmpfs (rw,nosuid,nodev)
none on /var/run type tmpfs (rw,nosuid,mode=0755)
none on /var/lock type tmpfs (rw,noexec,nosuid,nodev)
none on /lib/init/rw type tmpfs (rw,nosuid,mode=0755)
/dev/xvda1 on /boot type ext3 (rw,noatime)
/dev/xvdh1 on /mnt type vfat (rw) [METADATA]
EOF
)
          expect do
            subject.mount_volume(
              { :device => '/dev/xvdh1' }, '/var/spool/softlayer')
          end.to raise_error(described_class::VolumeManager::VolumeError)
        end

        it 'raises volume error when a different device is already mounted to the specified mountpoint' do
          platform_class.
            should_receive(:execute).
            with('mount 2>&1', {}).
            and_return(
<<EOF
/dev/xvda2 on / type ext3 (rw,noatime,errors=remount-ro)
proc on /proc type proc (rw,noexec,nosuid,nodev)
none on /sys type sysfs (rw,noexec,nosuid,nodev)
none on /sys/kernel/debug type debugfs (rw)
none on /sys/kernel/security type securityfs (rw)
none on /dev type devtmpfs (rw,mode=0755)
none on /dev/pts type devpts (rw,noexec,nosuid,gid=5,mode=0620)
none on /dev/shm type tmpfs (rw,nosuid,nodev)
none on /var/run type tmpfs (rw,nosuid,mode=0755)
none on /var/lock type tmpfs (rw,noexec,nosuid,nodev)
none on /lib/init/rw type tmpfs (rw,nosuid,mode=0755)
/dev/xvda1 on /boot type ext3 (rw,noatime)
/dev/xvdh2 on /var/spool/softlayer type vfat (rw) [METADATA]
EOF
)
          expect do
            subject.mount_volume(
              { :device => '/dev/xvdh1' }, '/var/spool/softlayer')
          end.to raise_error(described_class::VolumeManager::VolumeError)
        end

      end # mount_volume
    end # volume_manager
  end # under unix/linux
end # RightScale::Platform
