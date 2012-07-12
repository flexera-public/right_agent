describe RightScale::Platform do
  subject { RightScale::Platform }

  context 'under Linux' do
    context :installer do
      context :install do
        it 'should succeed if no packages are specified' do
          packages = []
          subject.installer.install(packages).should == true
        end

        it 'should succeed if all packages install successfully' do
          packages = ['syslog-ng']
          subject.installer.install(packages).should == true
        end

        it 'should fail if one more packages are not found' do
          packages = ['syslog-ng', 'l33thax0r-12345-very-unlikely-package']
          lambda { subject.installer.install(packages) }.should raise_error
        end
      end
    end
  end
end if RightScale::Platform.linux?
