#
# Copyright (c) 2012 RightScale Inc
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

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))

if RightScale::Platform.windows?
  module OsInfoExtensions
    def set_osinfo(osinfo)
      @os_info = osinfo
    end

    def get_osinfo
      @os_info
    end
  end

  describe RightScale::Platform do
    before(:all) do
      @platform = RightScale::Platform
    end

    context :volume_manager do
      context :is_attachable_volume_path do
        it 'allows paths with hyphens and underscores' do
          @platform.volume_manager.is_attachable_volume_path?('C:\\Some_crazy-path').should == true
        end

        it 'allows paths with periods' do
          @platform.volume_manager.is_attachable_volume_path?('C:\\Some.crazy.path').should == true
        end

        it 'allows paths with tildes' do
          @platform.volume_manager.is_attachable_volume_path?('C:\\~Some~crazy~path').should == true
        end
      end

      context :parse_volumes do
        it 'can parse volumes from diskpart output' do
          list_vol_resp = <<EOF
  Volume ###  Ltr  Label        Fs     Type        Size     Status     Info
  ----------  ---  -----------  -----  ----------  -------  ---------  --------
  Volume 0     C   2008Boot     NTFS   Partition     80 GB  Healthy    System
* Volume 1     D                NTFS   Partition   4094 MB  Healthy
  Volume 2                      NTFS   Partition   4094 MB  Healthy
EOF

          volume_hash_ary = [
            {:index => 0, :device => "C:", :label => "2008Boot", :filesystem => "NTFS", :type => "Partition", :total_size => 85899345920, :status => "Healthy", :info => "System"},
            {:index => 1, :device => "D:", :label => nil, :filesystem => "NTFS", :type => "Partition", :total_size => 4292870144, :status => "Healthy", :info => nil},
            {:index => 2, :device => nil, :label => nil, :filesystem => "NTFS", :type => "Partition", :total_size => 4292870144, :status => "Healthy", :info => nil}
          ]

          @platform.volume_manager.send(:parse_volumes, list_vol_resp).should == volume_hash_ary
        end

        it 'can parse volumes from diskpart output with mounted paths' do
          list_vol_resp = <<EOF
  Volume ###  Ltr  Label        Fs     Type        Size     Status     Info
  ----------  ---  -----------  -----  ----------  -------  ---------  --------
  Volume 0     C                NTFS   Partition     80 GB  Healthy    System
* Volume 1                      FAT32  Partition   1023 MB  Healthy
    C:\\Program Files\\RightScale\\Mount\\Softlayer\\
EOF

          volume_hash_ary = [
            {:index => 0, :device => "C:", :label => nil, :filesystem => "NTFS", :type => "Partition", :total_size => 85899345920, :status => "Healthy", :info => "System"},
            {:index => 1, :device => "C:\\Program Files\\RightScale\\Mount\\Softlayer\\", :label => nil, :filesystem => "FAT32", :type => "Partition", :total_size => 1072693248, :status => "Healthy", :info => nil}
          ]

          @platform.volume_manager.send(:parse_volumes, list_vol_resp).should == volume_hash_ary
        end

        it 'raises a parser error when diskpart output is malformed' do
          list_vol_resp = "foobarbaz"

          lambda { @platform.volume_manager.send(:parse_volumes, list_vol_resp) }.should raise_error(RightScale::Platform::VolumeManager::ParserError)
        end

        it 'can filter results with only one condition' do
          list_vol_resp = <<EOF
  Volume ###  Ltr  Label        Fs     Type        Size     Status     Info
  ----------  ---  -----------  -----  ----------  -------  ---------  --------
  Volume 0     C   2008Boot     NTFS   Partition     80 GB  Healthy    System
* Volume 1     D                NTFS   Partition   4094 MB  Healthy
  Volume 2                      NTFS   Partition   4094 MB  Healthy
EOF

          volume_hash_ary = [
            {:index => 1, :device => "D:", :label => nil, :filesystem => "NTFS", :type => "Partition", :total_size => 4292870144, :status => "Healthy", :info => nil}
          ]

          condition = {:device => "D:"}

          @platform.volume_manager.send(:parse_volumes, list_vol_resp, condition).should == volume_hash_ary
        end

        it 'can filter results with many conditions' do
          list_vol_resp = <<EOF
  Volume ###  Ltr  Label        Fs     Type        Size     Status     Info
  ----------  ---  -----------  -----  ----------  -------  ---------  --------
  Volume 0     C   2008Boot     NTFS   Partition     80 GB  Healthy    System
* Volume 1     D                NTFS   Partition   4094 MB  Healthy
  Volume 2                      NTFS   Partition   4094 MB  Healthy
EOF

          volume_hash_ary = [
            {:index => 1, :device => "D:", :label => nil, :filesystem => "NTFS", :type => "Partition", :total_size => 4292870144, :status => "Healthy", :info => nil}
          ]

          condition = {:device => "D:", :filesystem => "NTFS", :type => "Partition"}

          @platform.volume_manager.send(:parse_volumes, list_vol_resp, condition).should == volume_hash_ary
        end
      end

      context :assign_device do
        it 'assigns a device to a drive letter when a drive letter is specified' do
          script = <<EOF
rescan
list volume
select volume "0"
attribute volume clear readonly noerr

assign letter=S
EOF

          mount_resp = ''
          flexmock(@platform.volume_manager).should_receive(:run_script).with(script).once.and_return([0, mount_resp])

          @platform.volume_manager.assign_device('0', 'S:')
        end

        it 'assigns a device to a path when a mount point is specified' do
          osinfo = flexmock(:major => 6)

          @platform.volume_manager.extend(OsInfoExtensions)
          old_osinfo = @platform.volume_manager.get_osinfo
          @platform.volume_manager.set_osinfo(osinfo)

          script = <<EOF
rescan
list volume
select volume "0"
attribute volume clear readonly noerr

assign mount="C:\\Program Files\\RightScale\\Mount\\Softlayer"
EOF

          flexmock(@platform.volume_manager).should_receive(:run_script).with(script).once.and_return([0, ''])

          @platform.volume_manager.assign_device('0', "C:\\Program Files\\RightScale\\Mount\\Softlayer")
          @platform.volume_manager.set_osinfo(old_osinfo)
        end

        it 'raises an exception when an invalid drive letter is specified' do
          lambda{@platform.volume_manager.assign_device('0', 'C:')}.should raise_error(RightScale::Platform::VolumeManager::ArgumentError)
        end

        it 'raises an exception when an invalid path is specified' do
          lambda{@platform.volume_manager.assign_device('0', 'This is not a path')}.should raise_error(RightScale::Platform::VolumeManager::ArgumentError)
        end

        it 'raises an exception when a mount path is specified and OS is pre 2008' do
          osinfo = flexmock(:major => 5)

          @platform.volume_manager.extend(OsInfoExtensions)
          old_osinfo = @platform.volume_manager.get_osinfo
          @platform.volume_manager.set_osinfo(osinfo)

          lambda{@platform.volume_manager.assign_device(0, "C:\\Somepath")}.should raise_error(RightScale::Platform::VolumeManager::ArgumentError)
          @platform.volume_manager.set_osinfo(old_osinfo)
        end

        it 'does not assign the device if the device is already assigned' do
          script = <<EOF
rescan
list volume
select volume "0"
attribute volume clear readonly noerr

assign mount="C:\\Program Files\\RightScale\\Mount\\Softlayer"
EOF

          flexmock(@platform.volume_manager).should_receive(:run_script).with(script).once.and_return([0, ''])

          @platform.volume_manager.assign_device('0', "C:\\Program Files\\RightScale\\Mount\\Softlayer")
          flexmock(@platform.volume_manager).should_receive(:volumes).once.and_return({:index => '0', :device => "C:\\Program Files\\RightScale\\Mount\\Softlayer"})
          @platform.volume_manager.assign_device('0', "C:\\Program Files\\RightScale\\Mount\\Softlayer", :idempotent => true)
        end

        it 'does not clear readonly flag if :clear_readonly option is set to false' do
          script = <<EOF
rescan
list volume
select volume "0"


assign mount="C:\\Program Files\\RightScale\\Mount\\Softlayer"
EOF

          flexmock(@platform.volume_manager).should_receive(:run_script).with(script).once.and_return([0, ''])
          @platform.volume_manager.assign_device('0', "C:\\Program Files\\RightScale\\Mount\\Softlayer", {:clear_readonly => false})
        end

        it 'removes all previous assignments if :remove_all option is set to true' do
          script = <<EOF
rescan
list volume
select volume "0"
attribute volume clear readonly noerr
remove all noerr
assign mount="C:\\Program Files\\RightScale\\Mount\\Softlayer"
EOF

          flexmock(@platform.volume_manager).should_receive(:run_script).with(script).once.and_return([0, ''])
          @platform.volume_manager.assign_device('0', "C:\\Program Files\\RightScale\\Mount\\Softlayer", :remove_all => true)
        end
      end

      context :format_disk do
        it 'formats and assigns a drive to a drive letter when a drive letter is specified' do
          osinfo = flexmock(:major => 6)
          @platform.volume_manager.extend(OsInfoExtensions)
          old_osinfo = @platform.volume_manager.get_osinfo
          @platform.volume_manager.set_osinfo(osinfo)

          script = <<EOF
rescan
list disk
select disk 0
attribute disk clear readonly noerr
online disk noerr
clean
create partition primary
assign letter=S
format FS=NTFS quick
EOF

          flexmock(@platform.volume_manager).should_receive(:run_script).with(script).once.and_return([0,''])
          @platform.volume_manager.format_disk(0, 'S:')
          @platform.volume_manager.set_osinfo(old_osinfo)
        end

        it 'formats and assigns a drive to a path when a mount point is specified' do
          osinfo = flexmock(:major => 6)
          @platform.volume_manager.extend(OsInfoExtensions)
          old_osinfo = @platform.volume_manager.get_osinfo
          @platform.volume_manager.set_osinfo(osinfo)

          script = <<EOF
rescan
list disk
select disk 0
attribute disk clear readonly noerr
online disk noerr
clean
create partition primary
assign mount="C:\\Somepath"
format FS=NTFS quick
EOF

          flexmock(@platform.volume_manager).should_receive(:run_script).with(script).once.and_return([0,''])
          @platform.volume_manager.format_disk(0, 'C:\\Somepath')
          @platform.volume_manager.set_osinfo(old_osinfo)
        end

        it 'raises an exception when a mount path is specified and OS is pre 2008' do
          osinfo = flexmock(:major => 5)

          @platform.volume_manager.extend(OsInfoExtensions)
          old_osinfo = @platform.volume_manager.get_osinfo
          @platform.volume_manager.set_osinfo(osinfo)

          lambda{@platform.volume_manager.format_disk(0, "C:\\Somepath")}.should raise_error(RightScale::Platform::VolumeManager::ArgumentError)
          @platform.volume_manager.set_osinfo(old_osinfo)
        end

      end

      context :online_disk do
        it 'does not online the disk if the disk is already online' do
          script = <<EOF
rescan
list disk
select disk 0
attribute disk clear readonly noerr
online disk noerr
EOF

          flexmock(@platform.volume_manager).should_receive(:run_script).with(script).once.and_return([0, ''])

          @platform.volume_manager.online_disk(0)
          flexmock(@platform.volume_manager).should_receive(:disks).once.and_return({:index => 0, :status => "Online"})
          @platform.volume_manager.online_disk(0, :idempotent => true)
        end
      end
    end
  end
end