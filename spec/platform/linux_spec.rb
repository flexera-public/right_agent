require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))

describe RightScale::Platform do
  subject { RightScale::Platform }

  context 'under Linux' do
    context :installer do
      context :install do
        it 'should succeed if no packages are specified' do
          packages = []
          flexmock(subject.installer).should_receive(:run_installer_command).and_return('ok')
          subject.installer.install(packages).should == true
        end

        it 'should succeed if all packages install successfully' do
          packages = ['syslog-ng']
          flexmock(subject.installer).should_receive(:run_installer_command).and_return('ok')
          subject.installer.install(packages).should == true
        end

        it 'should fail if one more packages are not found' do
          if subject.installer.yum?
            failure_message = "No package l33th4x0r available."
          elsif subject.installer.aptitude?
            failure_message = "E: Couldn't find package l33th4x0r"
          elsif subject.installer.zypper?
            failure_message = "Package 'l33h4x0r' not found."
          end
          packages = ['syslog-ng', 'l33th4x0r']

          flexmock(subject.installer).should_receive(:run_installer_command).and_return(failure_message)

          lambda { subject.installer.install(packages) }.should raise_error
        end
      end
    end
  end
end if RightScale::Platform.linux?
