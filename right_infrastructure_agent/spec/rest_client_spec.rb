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

require 'json'
require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib', 'right_infrastructure_agent', 'rest_client'))

class ExceptionWithReason < Exception
  attr_reader :response

  def initialize(message, reason, encode_error = true)
    @response = encode_error ? {:error => reason}.to_json : reason
    super(message)
  end
end

describe RightScale::RightNetRestClient do

  include FlexMock::ArgumentTypes

  before(:each) do
    flexmock(RightScale::Log).should_receive(:error).and_return { |m| raise m[1] }.by_default
    flexmock(RightScale::Log).should_receive(:warn).and_return { |m| raise m[1] }.by_default
    @exception_stats = flexmock("exception_stats", :track => true)
    @usage_stats = flexmock("usage_stats", :update => 1, :finish => 2)
    @urls = "http://host1,http://host2"
    service = {:my => {:urls => @urls, :usage_stats => @usage_stats}}
    @rest = RightScale::RightNetRestClient.new(service, @exception_stats)
    @REST = flexmock(RightSupport::Net::REST)
    @balancer = flexmock(RightSupport::Net::RequestBalancer)
    @data = ["data"]
    @data_json = @data.to_json
  end

  context "query" do

    it "should make rest request" do
      @balancer.should_receive(:request).with(@urls, Hash, Proc).and_return("").and_yield("http://host1").once
      @REST.should_receive(:get).with("http://host1/this/1", nil).and_return("").once
      @rest.get(:my, "/this/1").should be_nil
    end

    it "should add params to end of uri for :get and :delete" do
      @balancer.should_receive(:request).with(@urls, Hash, Proc).and_return("").and_yield("http://host1").times(4)
      @REST.should_receive(:get).with("http://host1/this/1?foo=bar", nil).and_return("").once
      @REST.should_receive(:delete).with("http://host1/this/1?foo=bar", nil).and_return("").once
      @REST.should_receive(:put).with("http://host1/this/1", :foo => "bar").and_return("").once
      @REST.should_receive(:post).with("http://host1/this/1", :foo => "bar").and_return("").once
      @rest.get(:my, "/this/1", :foo => "bar").should be_nil
      @rest.put(:my, "/this/1", :foo => "bar").should be_nil
      @rest.post(:my, "/this/1", :foo => "bar").should be_nil
      @rest.delete(:my, "/this/1", :foo => "bar").should be_nil
    end

    it "should unserialize the response if not empty" do
      @balancer.should_receive(:request).with(@urls, Hash, Proc).and_return(@data_json).and_yield("http://host1").once
      @REST.should_receive(:get).with("http://host1/this/1", nil).and_return(@data_json).once
      @rest.get(:my, "/this/1").should == @data
    end

    it "should log query" do
      flexmock(RightScale::Log).should_receive(:info).with("MY [get] http://host1/this/1 {} (8 bytes, 2 sec)").once
      @balancer.should_receive(:request).with(@urls, Hash, Proc).and_return(@data_json).and_yield("http://host1").once
      @REST.should_receive(:get).with("http://host1/this/1", nil).and_return(@data_json).once
      @rest.get(:my, "/this/1").should == @data
    end

    it "should filter params when logging query" do
      flexmock(RightScale::Log).should_receive(:info).
              with(on { |arg| arg =~ /:a=>\"\*\*\*\*\"/ && arg =~ /:b=>\"ok\"/ }).once
      @balancer.should_receive(:request).with(@urls, Hash, Proc).and_return(@data_json).and_yield("http://host1").once
      @REST.should_receive(:get).with(on { |arg| arg =~ /a=secret/ && arg =~ /b=ok/ }, nil).and_return(@data_json).once
      @rest.get(:my, "/this/1", {:a => "secret", :b => "ok"}, :filter_params => [:a]).should == @data
    end

    it "should catch ResourceNotFound exception and return nil" do
      @balancer.should_receive(:request).with(@urls, Hash, Proc).and_raise(RestClient::ResourceNotFound).once
      @rest.get(:my, "/this/1").should be_nil
    end

    it "should catch and log exceptions and return nil" do
      flexmock(RightScale::Log).should_receive(:error).with(/Failed MY \[get\]/, Exception).once
      @balancer.should_receive(:request).with(@urls, Hash, Proc).and_raise(Exception).once
      @rest.get(:my, "/this/1").should be_nil
    end

    it "should raise unexpected exceptions after logging them if :raise_exceptions requested" do
      flexmock(RightScale::Log).should_receive(:error).with(/Failed MY \[get\]/, Exception).once
      @balancer.should_receive(:request).with(@urls, Hash, Proc).and_raise(Exception).once
      lambda { @rest.get(:my, "/this/1", {}, :raise_exceptions => true) }.should raise_error(Exception)
    end

    it "should raise QueryFailure with failure reason if known and :raise_exceptions requested" do
      flexmock(RightScale::Log).should_receive(:error).with(/Failed MY \[get\]/, Exception).once
      @balancer.should_receive(:request).with(@urls, Hash, Proc).and_raise(ExceptionWithReason.new("blah", "because")).once
      lambda { @rest.get(:my, "/this/1", {}, :raise_exceptions => true) }.
          should raise_error(RightScale::RightNetRestClient::QueryFailure, /because/)
    end

    it "should add reason to UnprocessableEntity exception" do
      @balancer.should_receive(:request).with(@urls, Hash, Proc).and_raise(RestClient::UnprocessableEntity).once
      lambda { @rest.get(:my, "/this/1") }.should raise_error(RightScale::RightNetRestClient::UnprocessableEntity)
    end

  end # query

  context "format" do

    it "should convert param to key=value format" do
      @rest.__send__(:format, {:foo => "bar"}).should == "foo=bar"
    end

    it "should escape param value" do
      @rest.__send__(:format, {:path => "/foo/bar"}).should == "path=%2Ffoo%2Fbar"
    end

    it "should break arrays into multiple params" do
      params = {:paths => ["/foo/bar", "/foo/bar2"]}
      @rest.__send__(:format, params).should == "paths[]=%2Ffoo%2Fbar&paths[]=%2Ffoo%2Fbar2"
    end

    it "should separate params with '&'" do
      params = {:foo => 111, :paths => ["/foo/bar", "/foo/bar2"], :bar => 999}
      response = @rest.__send__(:format, params)
      response.split("&").sort.should == ["bar=999", "foo=111", "paths[]=%2Ffoo%2Fbar", "paths[]=%2Ffoo%2Fbar2"]
    end

  end # format

  context "reason" do

    it "should extract reason" do
      e = ExceptionWithReason.new("blah blah blah", "because")
      @rest.__send__(:reason, e).should == "because"
    end

    it "should extract reason when not JSON encoded" do
      e = ExceptionWithReason.new("blah blah blah", "because", encode_error = false)
      @rest.__send__(:reason, e).should == "because"
    end

    it "should return empty string if no reason found" do
      e = Exception.new("blah blah blah")
      @rest.__send__(:reason, e).should == ""
    end

  end # reason

end
