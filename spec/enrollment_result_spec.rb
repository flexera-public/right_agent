# Copyright (c) 2009-2011 RightScale, Inc, All Rights Reserved Worldwide.
#
# THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO RIGHTSCALE
# AND CONSTITUTES A VALUABLE TRADE SECRET.  Any unauthorized use,
# reproduction, modification, or disclosure of this program is
# strictly prohibited.  Any use of this program by an authorized
# licensee is strictly subject to the terms and conditions,
# including confidentiality obligations, set forth in the applicable
# License Agreement between RightScale.com, Inc. and
# the licensee.

require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))
require File.expand_path(File.join(File.dirname(__FILE__), '..' , 'lib', 'right_agent', 'enrollment_result'))

describe RightScale::EnrollmentResult do
  before(:each) do
    @key = 'topsecret'
    @result = RightScale::EnrollmentResult.new(6, Time.now, 'router cert', 'my cert', 'my private key', @key)
    @message  = RightScale::EnrollmentResult.dump(@result)
  end

  it 'should serialize and unserialize correctly' do
    r2 = RightScale::EnrollmentResult.load(@message, @key)
    @result.should == r2
  end

  context "supporting different versions" do
    RightScale::EnrollmentResult::SUPPORTED_VERSIONS.each do |v|
      it "should support version #{v}" do
        @result = RightScale::EnrollmentResult.new(v, Time.now, 'router cert', 'my cert', 'my private key', @key)
        serialized = RightScale::EnrollmentResult.dump(@result)
        @result2 = RightScale::EnrollmentResult.load(serialized, @key)
        @result.should == @result2
      end
    end
  end

  it 'should fail to decrypt if tampered with' do
    #Simulate some ciphertext tampering.
    @message.gsub! /[0-9]/, '1'
    @message.gsub! /"r_s_version":"[0-9]+"/, '"r_s_version":"6"'

    lambda do
      RightScale::EnrollmentResult.load(@message, @key)
    end.should raise_error(RightScale::EnrollmentResult::IntegrityFailure)
  end

  it 'should fail to decrypt if the key is wrong' do
    lambda do
      RightScale::EnrollmentResult.load(@message, @key + "evil")
    end.should raise_error(RightScale::EnrollmentResult::IntegrityFailure)
  end
end
