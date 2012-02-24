module RightScale
  describe Platform do
    subject { RightScale::Platform }
    
    context :installer do
      context :install do
        specify { lambda { subject.installer.install([]) }.should raise_exception }
      end
    end
  end
end