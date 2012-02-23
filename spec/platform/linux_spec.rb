module RightScale
  describe Platform do
    subject { RightScale::Platform }
    
    context :installer do
      context :install do
        it 'should succeed if no packages are specified' do
          packages = []
          RightScale::Platform.installer.install(packages).should == true
        end
      end
    end
  end
end