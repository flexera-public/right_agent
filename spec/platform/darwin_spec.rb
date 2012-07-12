describe 'RightScale::Platform' do
  subject { RightScale::Platform }

  context 'under Darwin' do
    context :installer do
      context :install do
        specify { lambda { subject.installer.install([]) }.should raise_exception }
      end
    end
  end
end if RightScale::Platform.darwin?
