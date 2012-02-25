module RightScale
  describe Platform do
    
    context :installer do
      context :install do
        it 'should succeed if no packages are specified' do
          packages = []
          RightScale::Platform.installer.install(packages).should == true
        end
        
        it 'should succeed if all packages install successfully' do
          packages = ['syslog-ng']
          RightScale::Platform.installer.install(packages).should == true
        end
        
        it 'should fail if one more packages are not found' do
          packages = ['jdk-6u26-linux-x64']
          lambda { RightScale::Platform.installer.install(packages) }.should raise_error
        end
      end
    end
  end
end