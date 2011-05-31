#
# Copyright (c) 2009-2011 RightScale Inc
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

describe RightScale::Signature do
  
  include RightScale::SpecHelper

  before(:all) do
    @test_data = "Test Data"
    @cert, @key = issue_cert
    @sig = RightScale::Signature.new(@test_data, @cert, @key)
  end

  it 'should create signed data' do
    @sig.to_s.should_not be_empty
  end

  it 'should create signed data using either PEM or DER format' do
    @sig.data(:pem).should_not be_empty
    @sig.data(:der).should_not be_empty
  end

  it 'should verify the signature' do
    cert2, key2 = issue_cert
  
    @sig.should be_a_match(@cert)
    @sig.should_not be_a_match(cert2)
  end

  it 'should load from serialized signature' do
    sig2 = RightScale::Signature.from_data(@sig.data)
    sig2.should_not be_nil
    sig2.should be_a_match(@cert)
  end

  it 'should load from serialized signature using either PEM or DER format' do
    sig2 = RightScale::Signature.from_data(@sig.data(:pem))
    sig2.should_not be_nil
    sig2.should be_a_match(@cert)
    sig2 = RightScale::Signature.from_data(@sig.data(:der))
    sig2.should_not be_nil
    sig2.should be_a_match(@cert)
  end

end
