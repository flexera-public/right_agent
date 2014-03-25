#--
# Copyright (c) 2013 RightScale, Inc, All Rights Reserved Worldwide.
#
# THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO RIGHTSCALE
# AND CONSTITUTES A VALUABLE TRADE SECRET.  Any unauthorized use,
# reproduction, modification, or disclosure of this program is
# strictly prohibited.  Any use of this program by an authorized
# licensee is strictly subject to the terms and conditions,
# including confidentiality obligations, set forth in the applicable
# License Agreement between RightScale.com, Inc. and
# the licensee.
#++

require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib', 'right_agent', 'http_exceptions'))

describe RightScale::HttpException do

  class HttpTest < RightScale::HttpException; end

  before(:each) do
    @exception = HttpTest.new(999, "failed")
  end

  context :initialize do
    it "stores HTTP code and body" do
      @exception.http_code.should == 999
      @exception.http_body.should == "failed"
    end

    it "allows generic description to be set" do
      @exception.message = "Test"
      @exception.to_s.should == "Test: failed"
    end
  end

  context :inspect do
    it "displays generic description and detailed message" do
      @exception.inspect.should == "HttpTest: failed"
    end
  end

  context :to_s do
    it "inspects the exception" do
      @exception.inspect.should == "HttpTest: failed"
    end
  end

  context :message do
    it "returns generic description" do
      @exception.message = "Test"
      @exception.message.should == "Test"
    end

    it "defaults to class name" do
      @exception.message.should == "HttpTest"
    end
  end

end # RightScale::HttpException

describe RightScale::HttpExceptions do

  before(:each) do
    @response = RightScale::Response.new({:location => "here"})
  end

  it "initializes list of standard HTTP exceptions" do
    RightScale::HttpExceptions::HTTP_EXCEPTIONS_MAP.size.should > 50
    RightScale::HttpExceptions::HTTP_EXCEPTIONS_MAP[400].should == RightScale::HttpExceptions::BadRequest
  end

  context :create do
    it "creates instance of standard exception" do
      e = RightScale::HttpExceptions.create(500, "failed", @response)
      e.class.should == RightScale::HttpExceptions::InternalServerError
    end

    it "creates exception whose message is the generic description" do
      e = RightScale::HttpExceptions.create(500, "failed", @response)
      e.message.should == "500 Internal Server Error"
      e.inspect.should == "500 Internal Server Error: failed"
    end

    it "creates RequestFailed exception if the HTTP code is not recognized" do
      e = RightScale::HttpExceptions.create(999, "failed", @response)
      e.class.should == RightScale::HttpExceptions::RequestFailed
      e.message.should == "HTTP status code 999"
      e.inspect.should == "HTTP status code 999: failed"
    end
  end

  context :convert do
    it "converts RestClient exception to HttpException" do
      bad_request = RestClient::Exceptions::EXCEPTIONS_MAP[400].new(nil, 400)
      RightScale::HttpExceptions.convert(bad_request).should be_a RightScale::HttpExceptions::BadRequest
    end
  end

end # RightScale::HttpExceptions
