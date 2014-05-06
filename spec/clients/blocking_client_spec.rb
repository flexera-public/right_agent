#--
# Copyright (c) 2013-2014 RightScale Inc
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
#++

require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'lib', 'right_agent', 'clients', 'blocking_client'))

describe RightScale::BlockingClient do

  include FlexMock::ArgumentTypes

  before(:each) do
    @log = flexmock(RightScale::Log)
    @log.should_receive(:error).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @log.should_receive(:warning).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @url = "http://my.com"
    @urls = [@url]
    @host = @url
    @path = "/foo/bar"
    @balancer = flexmock("balancer")
    flexmock(RightSupport::Net::RequestBalancer).should_receive(:new).and_return(@balancer).by_default
    @later = (@now = Time.now)
    flexmock(Time).should_receive(:now).and_return { @later += 1 }
  end

  context :initialize do
    before(:each) do
      @options = {}
      @client = RightScale::BlockingClient.new(@options)
    end

    it "does not initialize use of proxy if not defined in environment" do
      flexmock(RestClient).should_receive(:proxy=).never
      RightScale::BlockingClient.new(@options)
    end

    ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY'].each do |proxy|
      context "when #{proxy} defined in environment" do
        after(:each) do
          ENV.delete(proxy)
        end

        it "initializes use of proxy" do
          ENV[proxy] = "https://my.proxy.com"
          flexmock(RestClient).should_receive(:proxy=).with("https://my.proxy.com").once
          RightScale::BlockingClient.new(@options)
        end

        it "infers http scheme for proxy address" do
          ENV[proxy] = "1.2.3.4"
          flexmock(RestClient).should_receive(:proxy=).with("http://1.2.3.4").once
          RightScale::BlockingClient.new(@options)
        end
      end
    end

    it "constructs health check proc" do
      @client.health_check_proc.should be_a Proc
    end

    context "health check proc" do
      before(:each) do
        @http_client = flexmock("http client")
        flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_return(@http_client).by_default
      end

      it "removes user and password from URL when checking health" do
        @url = "http://111:secret@me.com"
        @client = RightScale::BlockingClient.new(@options.merge(:health_check_path => "/health-check-me"))
        flexmock(@client).should_receive(:request).with(:get, "", "http://me.com/health-check-me", {}, Hash).once
        @client.health_check_proc.call(@url)
      end

      it "uses default path if none specified" do
        @client = RightScale::BlockingClient.new(@options)
        flexmock(@client).should_receive(:request).with(:get, "", "http://my.com/health-check", {}, Hash).once
        @client.health_check_proc.call(@url)
      end

      it "appends health check path to any existing path" do
        @url = "http://my.com/foo"
        @client = RightScale::BlockingClient.new(@options)
        flexmock(@client).should_receive(:request).with(:get, "", "http://my.com/foo/health-check", {}, Hash).once
        @client.health_check_proc.call(@url)
      end

      it "uses fixed timeout values" do
        @client = RightScale::BlockingClient.new(:open_timeout => 5, :request_timeout => 30)
        flexmock(@client).should_receive(:request).with(:get, "", String, {}, {:open_timeout => 2, :timeout => 5}).once
        @client.health_check_proc.call(@url)
      end

      it "sets API version if specified" do
        @client = RightScale::BlockingClient.new(:api_version => "2.0")
        flexmock(@client).should_receive(:request).with(:get, "", String, {}, hsh(:headers => {"X-API-Version" => "2.0"})).once
        @client.health_check_proc.call(@url)
      end
    end
  end

  context :options do
    before(:each) do
      @options = {}
      @verb = :get
      @params = {}
      @headers = {}
      @client = RightScale::BlockingClient.new(@options)
    end

    it "sets default open and request timeouts" do
      connect_options, request_options = @client.options(@verb, @path, @params, @headers, @options)
      connect_options.should == {}
      request_options[:open_timeout].should == RightScale::BalancedHttpClient::DEFAULT_OPEN_TIMEOUT
      request_options[:timeout].should == RightScale::BalancedHttpClient::DEFAULT_REQUEST_TIMEOUT
    end

    it "sets specified open and request timeouts" do
      @options = {:open_timeout => 1, :request_timeout => 2}
      _, request_options = @client.options(@verb, @path, @params, @headers, @options)
      request_options[:open_timeout].should == 1
      request_options[:timeout].should == 2
    end

    it "sets request headers" do
      @headers = {:some => "header"}
      _, request_options = @client.options(@verb, @path, @params, @headers, @options)
      request_options[:headers].should == @headers
    end

    [:get, :delete].each do |verb|
      context "with #{verb.inspect}" do
        it "uses form-encoded query option for parameters" do
          @params = {:some => "data", :more => ["a", "b"]}
          _, request_options = @client.options(verb, @path, @params, @headers, @options)
          request_options[:query].should == "?some=data&more[]=a&more[]=b"
          request_options[:payload].should be nil
        end

        it "omits query option if there are no parameters" do
          _, request_options = @client.options(verb, @path, @params, @headers, @options)
          request_options.has_key?(:query).should be false
        end
      end
    end

    [:post, :put].each do |verb|
      context "with #{verb.inspect}" do
        it "uses JSON-encoded payload options for parameters" do
          @params = {:some => "data"}
          _, request_options = @client.options(verb, @path, @params, @headers, @options)
          request_options[:query].should be_nil
          request_options[:payload].should == JSON.dump(@params)
          request_options[:headers][:content_type].should == "application/json"
        end
      end
    end
  end

  context "requesting" do
    before(:each) do
      @options = {}
      @query = "?some=data&more[]=a&more[]=b"
      @connect_options = {}
      @request_options = {:open_timeout => 2, :request_timeout => 5, :headers => {:accept => "application/json"}, :query => @query}
      @result = {"out" => 123}
      @body = JSON.dump({:out => 123})
      @headers = {:status => "200 OK"}
      @response = flexmock("response", :code => 200, :body => @body, :headers => @headers).by_default
      @http_client = flexmock("http client")
      flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_return(@http_client).by_default
      @client = RightScale::BlockingClient.new(@options)
    end

    context :request do
      it "makes request" do
        @http_client.should_receive(:get).with(@host + @path + @query, @request_options).and_return(@response).once
        @client.request(:get, @path, @host, @connect_options, @request_options)
        @request_options[:query].should be nil
      end

      it "processes response and returns result plus response code, body, and headers" do
        @http_client.should_receive(:get).with(@host + @path + @query, @request_options).and_return(@response).once
        result = @client.request(:get, @path, @host, @connect_options, @request_options)
        result.should == [@result, 200, @body, @headers]
      end

      it "stores the connection" do
        @http_client.should_receive(:get).with(@host + @path + @query, @request_options).and_return(@response).once
        @client.request(:get, @path, @host, @connect_options, @request_options)
        @client.connections[@path].should == {:host => @host, :path => @path, :expires_at => @later + 5}
      end

      it "returns nil if response is nil" do
        @http_client.should_receive(:get).with(@host + @path + @query, @request_options).and_return(nil).once
        result = @client.request(:get, @path, @host, @connect_options, @request_options)
        result.should == [nil, nil, nil, nil]
      end
    end

    context :poll do
      before(:each) do
        @stop_at = @later + 10
        @connection = {:host => @host, :path => @path, :expires_at => @later}
        @nil_response = flexmock("nil response", :code => 200, :body => "null", :headers => @headers).by_default
      end

      it "uses existing connection info to form url" do
        @http_client.should_receive(:get).with(@host + @path + @query, @request_options).and_return(@response).once
        @client.poll(@connection, @request_options, @stop_at)
      end

      it "makes request" do
        @http_client.should_receive(:get).with(@host + @path + @query, @request_options).and_return(@response).once
        result = @client.poll(@connection, @request_options, @stop_at)
        result.should == [@result, 200, @body, @headers]
      end

      it "makes at least one request regardless of stop time" do
        @http_client.should_receive(:get).with(@host + @path + @query, @request_options).and_return(@nil_response).once
        result = @client.poll(@connection, @request_options, @now - 10)
        result.should == [nil, 200, "null", @headers]
      end

      it "stops polling if there is a non-nil result" do
        @http_client.should_receive(:get).with(@host + @path + @query, @request_options).and_return(@nil_response).once.ordered
        @http_client.should_receive(:get).with(@host + @path + @query, @request_options).and_return(@response).once.ordered
        result = @client.poll(@connection, @request_options, @stop_at)
        result.should == [@result, 200, @body, @headers]
      end

      it "stops polling if there is a nil result but it is time to stop" do
        @http_client.should_receive(:get).with(@host + @path + @query, @request_options).and_return(@nil_response).twice
        result = @client.poll(@connection, @request_options, @later + 2)
        result.should == [nil, 200, "null", @headers]
      end
    end

    context :request_once do
      it "makes request and returns results" do
        @http_client.should_receive(:get).with(@url, @request_options).and_return(@response).once
        result = @client.send(:request_once, :get, @url, @request_options)
        result.should == [@result, 200, @body, @headers]
      end

      it "returns nil if response is nil" do
        @http_client.should_receive(:get).with(@url, @request_options).and_return(nil).once
        result = @client.send(:request_once, :get, @url, @request_options)
        result.should == [nil, nil, nil, nil]
      end
    end

    context :close do
      it "deletes all persistent connections" do
        @http_client.should_receive(:get).with(@host + @path + @query, @request_options).and_return(@response).once
        @client.request(:get, @path, @host, @connect_options, @request_options)
        @client.connections.should_not be_empty
        @client.close("terminating").should be true
        @client.connections.should be_empty
      end
    end
  end
end
