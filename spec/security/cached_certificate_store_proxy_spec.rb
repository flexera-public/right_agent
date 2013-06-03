#
# Copyright (c) 2009-2013 RightScale Inc
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

describe RightScale::CachedCertificateStoreProxy do
  
  include RightScale::SpecHelper

  before(:all) do
    @cert, @key = issue_cert
    @signer, key = issue_cert
    @target, key = issue_cert
    @store = flexmock("Store")
    @proxy = RightScale::CachedCertificateStoreProxy.new(@store)
  end

  it 'should not raise and return nil for non existent certificates' do
    res = nil
    @store.should_receive(:get_target).with(nil).and_return(nil)
    lambda { res = @proxy.get_target(nil) }.should_not raise_error
    res.should == nil
    @store.should_receive(:get_signer).with(nil).and_return(nil)
    lambda { res = @proxy.get_signer(nil) }.should_not raise_error
    res.should == nil
  end

  it 'should return target certificates' do
    @store.should_receive(:get_target).with('anything').and_return(@target)
    @proxy.get_target('anything').should == @target
  end
  
  it 'should return signer certificates' do
    @store.should_receive(:get_signer).with('anything').and_return(@signer)
    @proxy.get_signer('anything').should == @signer
  end

  it 'should return receiver certificate and key' do
    @store.should_receive(:get_receiver).with('anything').and_return([@cert, @key])
    @proxy.get_receiver('anything').should == [@cert, @key]
  end

end
