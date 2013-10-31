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

shared_examples_for 'supports windows platform statics' do
  it 'should be Windows' do
    subject.unix?.should be_false
    subject.windows?.should be_true
    subject.linux?.should be_false
    subject.darwin?.should be_false
  end
end # supports windows platform statics

shared_examples_for 'supports windows platform initialization' do
  it 'should query os info during initialize' do
    instrument_os_info(6, 1, 7601)
    platform_instance.send(:initialize_genus)
    platform_instance.release.should == '6.1.7601'
    platform_instance.codename.should == ''
  end
end # supports windows platform initialization

shared_examples_for 'supports windows platform filesystem' do
  context '#find_executable_in_path' do
    let(:pathexts)      { %w[.EXE .BAT] }
    let(:paths)         { %w[C:\Windows\system32 C:\Windows C:\Windows\System32\Wbem] }
    let(:pathext_env)   { pathexts.join(';') }
    let(:path_env)      { paths.join(';') }
    let(:expected_path) { 'C:/Windows/foo.EXE' }

    it 'should find executable' do
      mock_env = flexmock(::ENV)
      mock_env.should_receive(:[]).with('PATHEXT').and_return(pathext_env)
      mock_env.should_receive(:[]).with('PATH').and_return(path_env)

      all_paths = [::Dir.getwd.gsub("\\", '/')] + paths
      foo_found = false
      all_paths.each do |path|
        pathexts.each do |pathext|
          unless foo_found
            foo_path = ::File.join(path.gsub("\\", '/'), 'foo' + pathext)
            foo_matched = foo_path == expected_path
            file_class.should_receive(:executable?).
              with(foo_path).
              and_return(foo_matched).
              twice
            foo_found = foo_matched
          end
          bar_path = ::File.join(path.gsub("\\", '/'), 'bar' + pathext)
          file_class.should_receive(:executable?).with(bar_path).and_return(false).twice
        end
      end

      subject.find_executable_in_path('foo').should == expected_path
      subject.has_executable_in_path('foo').should be_true
      subject.find_executable_in_path('bar').should be_nil
      subject.has_executable_in_path('bar').should be_false
    end
  end # find_executable_in_path

  context 'paths' do
    context 'constants' do
      before(:each) do
        # win32/dir-based constants.
        subject.should_receive(:common_app_data_dir).and_return('C:/ProgramData')
        subject.should_receive(:program_files_dir).and_return('C:/Program Files (x86)')

        # ENV-based constants.
        @mock_env = flexmock(::ENV)
        @mock_env.should_receive(:[]).with('SystemRoot').and_return("C:\\Windows")
        @mock_env.should_receive(:[]).with('USERPROFILE').and_return("C:\\Users\\foo")
      end

      it 'should return windows path constants' do
        # windows-specific constants.
        subject.company_app_data_dir.should == 'C:/ProgramData/RightScale'
        subject.company_program_files_dir.should == 'C:/Program Files (x86)/RightScale'
        subject.system_root.should == 'C:/Windows'
        subject.user_home_dir.should == 'C:/Users/foo'

        # constants available to all platforms.
        subject.right_agent_cfg_dir.should == 'C:/ProgramData/RightScale/right_agent'
        subject.right_scale_static_state_dir.should == 'C:/ProgramData/RightScale/rightscale.d'
        subject.right_link_static_state_dir.should == 'C:/ProgramData/RightScale/rightscale.d/right_link'
        subject.right_link_dynamic_state_dir.should == 'C:/ProgramData/RightScale/right_link'
        subject.spool_dir.should == 'C:/ProgramData/RightScale/spool'
        subject.ssh_cfg_dir.should == 'C:/Users/foo/.ssh'
        subject.cache_dir.should == 'C:/ProgramData/RightScale/cache'
        subject.log_dir.should == 'C:/ProgramData/RightScale/log'
        subject.source_code_dir.should == 'C:/ProgramData/RightScale/src'
        subject.pid_dir.should == 'C:/ProgramData/RightScale/run'

        @mock_env.
          should_receive(:[]).
          with('RS_RIGHT_LINK_HOME').
          and_return("C:\\PROGRA~2\\RIGHTS~1\\RIGHTL~1")
        file_class.
          should_receive(:normalize_path).
          with('C:/PROGRA~2/RIGHTS~1/RIGHTL~1').
          and_return('C:/PROGRA~2/RIGHTS~1/RIGHTL~1').
          once
        subject.right_link_home_dir.should == 'C:/PROGRA~2/RIGHTS~1/RIGHTL~1'
        subject.private_bin_dir.should == 'C:/PROGRA~2/RIGHTS~1/RIGHTL~1/bin'
        subject.sandbox_dir.should == 'C:/PROGRA~2/RIGHTS~1/RIGHTL~1/sandbox'
      end

      it 'should generate right_link_home_dir when not set in ENV' do
        @mock_env.should_receive(:[]).with('RS_RIGHT_LINK_HOME').and_return(nil)
        file_class.
          should_receive(:normalize_path).
          with('C:/Program Files (x86)/RightScale/RightLink').
          and_return('C:/PROGRA~2/RIGHTS~1/RIGHTL~1').
          once
        subject.right_link_home_dir.should == 'C:/PROGRA~2/RIGHTS~1/RIGHTL~1'
      end
    end

    context '#temp_dir' do
      it 'should query temp_dir by calling GetTempPath API' do
        temp_path_from_api = "C:\\Users\\foo\\AppData\\Local\\Temp\\"
        instrument_get_temp_path_api(temp_path_from_api) { temp_path_from_api.length }
        subject.temp_dir.should == 'C:/Users/foo/AppData/Local/Temp'
      end
    end

    context '#long_path_to_short_path' do
      it 'should convert existing long path to short path' do
        long_path = 'C:\Program Files (x86)\RightScale\RightLink'
        short_path = 'C:/PROGRA~2/RIGHTS~1/RIGHTL~1'
        instrument_get_short_path_name_api(long_path, short_path) { short_path.length }
        file_class.should_receive(:exists?).with(long_path).and_return(true).once
        subject.long_path_to_short_path(long_path).should == short_path
      end

      it 'should convert existing parent of missing long path to short path' do
        long_path_parent = 'C:/Program Files (x86)/RightScale'
        long_path = long_path_parent + '/RightLink'
        short_path_parent = 'C:/PROGRA~2/RIGHTS~1'
        short_path = short_path_parent + '/RightLink'
        instrument_get_short_path_name_api(long_path_parent, short_path_parent) { short_path_parent.length }
        file_class.should_receive(:exists?).with(long_path).and_return(false).once
        file_class.should_receive(:exists?).with(long_path_parent).and_return(true).once
        subject.long_path_to_short_path(long_path).should == short_path
      end
    end

    context '#pretty_path' do
      it 'should pretty path' do
        ugly = 'c:\/make//\/me\pretty'
        pretty_for_ruby = 'c:/make/me/pretty'
        pretty_for_cmd_exe = 'c:\make\me\pretty'
        subject.pretty_path(ugly).should == pretty_for_ruby
        subject.pretty_path(ugly, true).should == pretty_for_cmd_exe
        subject.pretty_path(pretty_for_ruby) == pretty_for_ruby
        subject.pretty_path(pretty_for_cmd_exe) == pretty_for_ruby
        subject.pretty_path(pretty_for_ruby, true) == pretty_for_cmd_exe
        subject.pretty_path(pretty_for_cmd_exe, true) == pretty_for_cmd_exe
      end
    end

    context '#ensure_local_drive_path' do
      before(:each) do
        flexmock(::ENV).should_receive(:[]).with('HOMEDRIVE').and_return('C:')
      end

      it 'should do nothing if path is already on home drive' do
        path = 'c:\already\local.txt'
        subject.ensure_local_drive_path(path, 'foo').should == path
      end

      it 'should copy file to temp directory if not local' do
        network_path = 'z:/from/network/drive.txt'
        local_path = 'c:/temp/foo/drive.txt'
        subject.should_receive(:temp_dir).and_return('c:/temp')
        mock_file_utils = flexmock(::FileUtils)
        mock_file_utils.should_receive(:mkdir_p).with('c:/temp/foo').and_return(true).once
        file_class.should_receive(:directory?).with(network_path).and_return(false).once
        mock_file_utils.should_receive(:cp).with(network_path, local_path).and_return(true).once
        subject.ensure_local_drive_path(network_path, 'foo').should == local_path
      end
    end
  end # paths

  context '#create_symlink' do
    it 'should create directory symlink' do
      from_path = 'c:\foo\bar'
      to_path = 'c:\foo\baz'
      file_class.should_receive(:directory?).with(from_path).and_return(true)
      instrument_create_symbolic_link_api(from_path, to_path, 1) { 1 }
      subject.create_symlink(from_path, to_path).should == 0
    end

    it 'should create file symlink' do
      from_path = 'c:\foo\bar.txt'
      to_path = 'c:\baz\bar.txt'
      file_class.should_receive(:directory?).with(from_path).and_return(false)
      instrument_create_symbolic_link_api(from_path, to_path, 0) { 1 }
      subject.create_symlink(from_path, to_path).should == 0
    end

    it 'should raise Win32Error on failure' do
      from_path = 'c:\some\file.txt'
      to_path = 'c:\no_access\hmm.txt'
      file_class.should_receive(:directory?).with(from_path).and_return(false)
      instrument_create_symbolic_link_api(from_path, to_path, 0) { 0 }
      instrument_win32_error(5, 'Access is denied.')
      expect { subject.create_symlink(from_path, to_path) }.
        to raise_error(
          described_class::Win32Error,
          "Failed to create link from #{from_path.inspect} to #{to_path.inspect}\nWin32 error code = 5\nAccess is denied.")
    end
  end # create_symlink
end # supports windows platform filesystem

shared_examples_for 'supports windows platform shell' do
  # required by 'supports any platform shell'
  def instrument_booted_at(booted_at)
    # example:
    # >echo | wmic OS Get LastBootUpTime 2>&1
    # LastBootUpTime
    # 20131025093127.375199-420
    bat = ::Time.at(booted_at.to_i)  # same bat time ...
    platform_class.
      should_receive(:execute).
      with('echo | wmic OS Get LastBootUpTime 2>&1', {}).
      and_return(
        '%04d%02d%02d%02d%02d%02d.%06d%03d' %
          [bat.year, bat.month, bat.day,
           bat.hour, bat.min, bat.sec,
           bat.usec, bat.utc_offset / 60]
      )
  end

  it_should_behave_like 'supports any platform shell'

  context 'paths' do
    before(:each) do
      # win32/dir-based constants.
      flexmock(platform_class.filesystem).
        should_receive(:sandbox_dir).
        and_return('C:/PROGRA~2/RIGHTS~1/RIGHTL~1/sandbox')

      # ENV-based constants.
      @mock_env = flexmock(::ENV)
      @mock_env.should_receive(:[]).
        with('RS_RUBY_EXE').
        and_return('C:/PROGRA~2/RIGHTS~1/RIGHTL~1/sandbox/ruby/bin/ruby.exe').
        by_default
    end

    it 'should return path constants for windows' do
      subject.null_output_name.should == 'NUL'
      file_class.
        should_receive(:normalize_path).
        with('C:/PROGRA~2/RIGHTS~1/RIGHTL~1/sandbox/ruby/bin/ruby.exe').
        and_return('C:/PROGRA~2/RIGHTS~1/RIGHTL~1/sandbox/ruby/bin/ruby.exe').
        once
      subject.sandbox_ruby.should == 'C:/PROGRA~2/RIGHTS~1/RIGHTL~1/sandbox/ruby/bin/ruby.exe'
    end

    it 'should generate right_link_home_dir when not set in ENV' do
      @mock_env.should_receive(:[]).with('RS_RUBY_EXE').and_return(nil)
      file_class.
        should_receive(:normalize_path).
        with('C:/PROGRA~2/RIGHTS~1/RIGHTL~1/sandbox/ruby/bin/ruby.exe').
        and_return('C:/PROGRA~2/RIGHTS~1/RIGHTL~1/sandbox/ruby/bin/ruby.exe').
        once
      subject.sandbox_ruby.should == 'C:/PROGRA~2/RIGHTS~1/RIGHTL~1/sandbox/ruby/bin/ruby.exe'
    end
  end # paths

  context 'commands' do
    context '#format_script_file_name' do
      let(:pathexts)    { %w[.EXE .BAT] }
      let(:pathext_env) { pathexts.join(';') }

      before(:each) do
        flexmock(::ENV).should_receive(:[]).with('PATHEXT').and_return(pathext_env)
      end

      it 'should format for powershell by default' do
        subject.format_script_file_name('foo').should == 'foo.ps1'
      end

      it 'should keep extension when executable' do
        subject.format_script_file_name('foo.bat').should == 'foo.bat'
      end

      it 'should append default extension when not executable' do
        subject.format_script_file_name('foo.bar').should == 'foo.bar.ps1'
      end
    end

    context '#format_executable_command' do
      it 'should format using given script path' do
        subject.format_executable_command('foo.bat', 'a/b', 'c d').should == 'foo.bat a/b "c d"'
      end

      it 'should insert cmd.exe if no extension was given' do
        subject.format_executable_command('foo', 'bar', '1 2').should == 'cmd.exe /C "foo bar "1 2""'
      end
    end

    context '#format_shell_command' do
      it 'should insert powershell.exe when extension is .ps1' do
        # RightRun runs child processes as 64-bit instead of 32-bit as would be
        # the default behavior when creating a child process from ruby.exe
        rrp = "C:\\PROGRA~1\\RIGHTS~1\\Shared\\RightRun.exe"
        script_path = 'c:\temp\foo.ps1'
        subject.should_receive(:right_run_path).and_return(rrp)

        # we wrap powershell script execution with additional checks for
        # $LastExitCode and $Error to ensure user script doesn't fail
        # mysteriously without any kind of error reporting (i.e. it saves us
        # some support calls).
        expected_cmd =
          "#{rrp} powershell.exe -command \"&{set-executionpolicy -executionPolicy RemoteSigned -Scope Process;" +
          " &#{script_path} bar; if ($NULL -eq $LastExitCode) { $LastExitCode = 0 };" +
          ' if ((0 -eq $LastExitCode) -and ($Error.Count -gt 0))' +
          " { $RS_message = 'Script exited successfully but $Error contained '+($Error.Count)+' error(s):';" +
          " write-output $RS_message; write-output $Error; $LastExitCode = 1 }; exit $LastExitCode}\""

        subject.format_shell_command(script_path, 'bar').should == expected_cmd
      end

      it 'should insert ruby.exe when extension is .rb' do
        ruby_exe_path = 'C:/PROGRA~2/RIGHTS~1/RIGHTL~1/sandbox/ruby/bin/ruby.exe'
        subject.should_receive(:sandbox_ruby).and_return(ruby_exe_path)
        subject.format_shell_command('foo.rb', 'bar').should == "#{ruby_exe_path} foo.rb bar"
      end

      it 'should format using given script path for other extensions' do
        subject.format_shell_command('foo.bat', 'a/b', 'c d').should == 'foo.bat a/b "c d"'
      end

      it 'should insert cmd.exe if no extension was given' do
        subject.format_shell_command('foo', 'bar', '1 2').should == 'cmd.exe /C "foo bar "1 2""'
      end
    end

    context '#format_ruby_command' do
      it 'should format for ruby' do
        ruby_exe_path = 'C:/PROGRA~2/RIGHTS~1/RIGHTL~1/sandbox/ruby/bin/ruby.exe'
        subject.should_receive(:sandbox_ruby).and_return(ruby_exe_path)
        subject.format_ruby_command('foo.rb', 'bar').should == "#{ruby_exe_path} foo.rb bar"
      end
    end
  end # commands
end # supports windows platform shell

shared_examples_for 'supports windows platform controller' do
  context '#reboot' do
    it 'should call InitiateSystemShutdown API' do
      instrument_initiate_system_shutdown_api(true)
      subject.reboot.should be_true
    end
  end # reboot

  context '#shutdown' do
    it 'should call InitiateSystemShutdown API' do
      instrument_initiate_system_shutdown_api(false)
      subject.shutdown.should be_true
    end
  end # shutdown
end # controller

shared_examples_for 'supports windows platform installer' do
  context :install do
    it 'should raise not implemented' do
      expect { subject.install(%w[foo bar]) }.
      to raise_error(
        ::RightScale::Exceptions::PlatformError,
        'No package installers supported on Windows')
    end
  end # install
end # supports windows platform installer

shared_examples_for 'supports windows platform rng' do
  context '#pseudorandom_bytes' do
    it 'should generate random bytes using ruby under Windows' do
      a = subject.pseudorandom_bytes(16)
      b = subject.pseudorandom_bytes(16)
      a.bytesize.should == 16
      b.bytesize.should == 16
      a.should_not == b  # equality is statistically impossible
      subject.pseudorandom_bytes(256).bytesize.should == 256
    end
  end # pseudorandom_bytes
end # supports windows platform rng

shared_examples_for 'supports windows platform process' do
  context '#resident_set_size' do
    it 'should return resident set size for current process' do
      expected_size = 12345
      instrument_get_process_memory_info_api(expected_size)
      subject.resident_set_size.should == expected_size
    end
  end # pseudorandom_bytes
end # supports windows platform rng

shared_examples_for 'supports windows platform volume manager' do
  let(:win2003_version) do
    ::RightScale::Platform::WindowsSystemInformation::Version.new(5, 2, 3790)
  end
  let(:win2008r2_version) do
    ::RightScale::Platform::WindowsSystemInformation::Version.new(6, 1, 7601)
  end

  before(:each) do
    flexmock(platform_class.windows_system_information).
      should_receive(:version).
      and_return(win2008r2_version)
  end
  
  context :is_attachable_volume_path? do
    it 'allows paths with hyphens and underscores' do
      subject.is_attachable_volume_path?('C:\\Some_crazy-path').should == true
    end

    it 'allows paths with periods' do
      subject.is_attachable_volume_path?('C:\\Some.crazy.path').should == true
    end

    it 'allows paths with tildes' do
      subject.is_attachable_volume_path?('C:\\~Some~crazy~path').should == true
    end
  end

  context :volumes do
    let(:volumes_script) do
<<EOF
rescan
list volume
EOF
    end
    
    it 'can parse volumes from diskpart output' do
      subject.
        should_receive(:run_diskpart_script).
        with(volumes_script, String).
        and_return(
<<EOF
  Volume ###  Ltr  Label        Fs     Type        Size     Status     Info
  ----------  ---  -----------  -----  ----------  -------  ---------  --------
  Volume 0     C   2008Boot     NTFS   Partition     80 GB  Healthy    System
* Volume 1     D                NTFS   Partition   4094 MB  Healthy
  Volume 2                      NTFS   Partition   4094 MB  Healthy
EOF
        ).once
      expected_volumes = [
        { :index => 0, :device => 'C:', :label => '2008Boot', :filesystem => 'NTFS', :type => 'Partition', :total_size => 85899345920, :status => 'Healthy', :info => 'System' },
        { :index => 1, :device => 'D:', :label => nil, :filesystem => 'NTFS', :type => 'Partition', :total_size => 4292870144, :status => 'Healthy', :info => nil },
        { :index => 2, :device => nil, :label => nil, :filesystem => 'NTFS', :type => 'Partition', :total_size => 4292870144, :status => 'Healthy', :info => nil }
      ]
      subject.volumes.should == expected_volumes
    end

    it 'can parse volumes from diskpart output with mounted paths' do
      subject.
        should_receive(:run_diskpart_script).
        with(volumes_script, String).
        and_return(
<<EOF
  Volume ###  Ltr  Label        Fs     Type        Size     Status     Info
  ----------  ---  -----------  -----  ----------  -------  ---------  --------
  Volume 0     C                NTFS   Partition     80 GB  Healthy    System
* Volume 1                      FAT32  Partition   1023 MB  Healthy
  C:\\Program Files\\RightScale\\Mount\\Softlayer\\
EOF
        ).once
      expected_volumes = [
        { :index => 0, :device => 'C:', :label => nil, :filesystem => 'NTFS', :type => 'Partition', :total_size => 85899345920, :status => 'Healthy', :info => 'System' },
        { :index => 1, :device => 'C:\\Program Files\\RightScale\\Mount\\Softlayer\\', :label => nil, :filesystem => 'FAT32', :type => 'Partition', :total_size => 1072693248, :status => 'Healthy', :info => nil }
      ]
      subject.volumes.should == expected_volumes
    end

    it 'raises a parser error when diskpart output is malformed' do  
      subject.
        should_receive(:run_diskpart_script).
        with(volumes_script, String).
        and_return('gibberish').
        once
      expect { subject.volumes }.
        to raise_error(RightScale::Platform::VolumeManager::ParserError)
    end

    it 'can filter results with only one condition' do
      subject.
        should_receive(:run_diskpart_script).
        with(volumes_script, String).
        and_return(
<<EOF
  Volume ###  Ltr  Label        Fs     Type        Size     Status     Info
  ----------  ---  -----------  -----  ----------  -------  ---------  --------
  Volume 0     C   2008Boot     NTFS   Partition     80 GB  Healthy    System
* Volume 1     D                NTFS   Partition   4094 MB  Healthy
  Volume 2                      NTFS   Partition   4094 MB  Healthy
EOF
        ).once
      expected_volumes = [
        { :index => 1, :device => 'D:', :label => nil, :filesystem => 'NTFS', :type => 'Partition', :total_size => 4292870144, :status => 'Healthy', :info => nil }
      ]             
      subject.volumes(:device => 'D:').should == expected_volumes
    end

    it 'can filter results with many conditions' do   
      subject.
        should_receive(:run_diskpart_script).
        with(volumes_script, String).
        and_return(
<<EOF
  Volume ###  Ltr  Label        Fs     Type        Size     Status     Info
  ----------  ---  -----------  -----  ----------  -------  ---------  --------
  Volume 0     C   2008Boot     NTFS   Partition     80 GB  Healthy    System
* Volume 1     D                NTFS   Partition   4094 MB  Healthy
  Volume 2                      NTFS   Partition   4094 MB  Healthy
EOF
        ).once
      expected_volumes = [
        {:index => 1, :device => 'D:', :label => nil, :filesystem => 'NTFS', :type => 'Partition', :total_size => 4292870144, :status => 'Healthy', :info => nil}
      ]
      conditions = { :device => 'D:', :filesystem => 'NTFS', :type => 'Partition' }
      subject.volumes(conditions).should == expected_volumes
    end
  end

  context :assign_device do
    it 'assigns a device to a drive letter when a drive letter is specified' do
      assign_device_script = <<EOF
rescan
list volume
select volume "0"
attribute volume clear readonly noerr

assign letter=S
EOF

      subject.
        should_receive(:run_diskpart_script).
        with(assign_device_script, String).
        and_return('').
        once
      subject.assign_device(0, 'S:')
    end

    it 'assigns a device to a path when a mount point is specified' do
      assign_device_script = <<EOF
rescan
list volume
select volume "2"
attribute volume clear readonly noerr

assign mount="C:\\Program Files\\RightScale\\Mount\\Softlayer"
EOF
      subject.
        should_receive(:run_diskpart_script).
        with(assign_device_script, String).
        and_return('').
        once
      subject.assign_device(2, "C:\\Program Files\\RightScale\\Mount\\Softlayer")
    end

    it 'raises an exception when an invalid drive letter is specified' do
      expect { subject.assign_device(0, 'C:') }.
        to raise_error(RightScale::Platform::VolumeManager::ArgumentError)
    end

    it 'raises an exception when an invalid path is specified' do
      expect { subject.assign_device(0, 'This is not a path') }.
        to raise_error(RightScale::Platform::VolumeManager::ArgumentError)
    end

    it 'raises an exception when a mount path is specified and OS is pre 2008' do
      subject.should_receive(:os_version).and_return(win2003_version)
      expect { subject.assign_device(0, "C:\\Somepath") }.
        to raise_error(RightScale::Platform::VolumeManager::ArgumentError)
    end

    it 'does not assign when already assigned by index' do
      subject.should_receive(:run_diskpart_script).never
      subject.
        should_receive(:volumes).
        and_return([{:index => '0', :device => "C:\\Program Files\\RightScale\\Mount\\Softlayer"}]).
        once
      subject.assign_device(0, "C:\\Program Files\\RightScale\\Mount\\Softlayer", :idempotent => true)
    end

    it 'does not assign when already assigned by device' do
      subject.should_receive(:run_diskpart_script).never
      subject.
        should_receive(:volumes).
        and_return([{:index => '0', :device => 'Z:'}]).
        once
      subject.assign_device('Z:', 'Z:', :idempotent => true)
    end

    it 'does not clear readonly flag if :clear_readonly option is set to false' do
      assign_device_script = <<EOF
rescan
list volume
select volume "0"


assign mount="C:\\Program Files\\RightScale\\Mount\\Softlayer"
EOF
      subject.
        should_receive(:run_diskpart_script).
        with(assign_device_script, String).
        and_return('').
        once
      subject.assign_device(0, "C:\\Program Files\\RightScale\\Mount\\Softlayer", :clear_readonly => false)
    end

    it 'removes all previous assignments if :remove_all option is set to true' do
      assign_device_script = <<EOF
rescan
list volume
select volume "0"
attribute volume clear readonly noerr
remove all noerr
assign mount="C:\\Program Files\\RightScale\\Mount\\Softlayer"
EOF
      subject.
        should_receive(:run_diskpart_script).
        with(assign_device_script, String).
        and_return('').
        once
      subject.assign_device(0, "C:\\Program Files\\RightScale\\Mount\\Softlayer", :remove_all => true)
    end
  end

  context :format_disk do
    it 'formats and assigns a drive to a drive letter when a drive letter is specified' do
      assign_device_script = <<EOF
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
      subject.
        should_receive(:run_diskpart_script).
        with(assign_device_script, String).
        and_return('').
        once
      subject.format_disk(0, 'S:')
    end

    it 'formats and assigns a drive to a path when a mount point is specified' do
      assign_device_script = <<EOF
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
      subject.
        should_receive(:run_diskpart_script).
        with(assign_device_script, String).
        and_return('').
        once
      subject.format_disk(0, 'C:\\Somepath')
    end

    it 'raises an exception when a mount path is specified and OS is pre 2008' do
      subject.should_receive(:os_version).and_return(win2003_version)
      expect { subject.format_disk(0, "C:\\Somepath") }.
        to raise_error(RightScale::Platform::VolumeManager::ArgumentError)
    end
  end # format_disk

  context :online_disk do
    it 'does not online the disk if the disk is already online' do
      online_disk_script = <<EOF
rescan
list disk
select disk 0
attribute disk clear readonly noerr
online disk noerr
EOF
      subject.
        should_receive(:run_diskpart_script).
        with(online_disk_script, String).
        and_return('').
        once
      subject.online_disk(0)
      subject.should_receive(:disks).and_return([{:index => 0, :status => 'Online'}]).once
      subject.online_disk(0, :idempotent => true)
    end
  end
end # supports windows platform volume manager
