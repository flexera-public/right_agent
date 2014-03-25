#--
# Copyright (c) 2013 RightScale Inc
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
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'lib', 'right_agent', 'clients', 'balanced_http_client'))

describe RightScale::BalancedHttpClient do

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
    flexmock(Time).should_receive(:now).and_return { @later += 0.01 }
  end

  context :initialize do
    it "initializes parameter filter list" do
      client = RightScale::BalancedHttpClient.new(@urls)
      client.instance_variable_get(:@filter_params).should == []
    end

    it "stores specified parameter filters" do
      client = RightScale::BalancedHttpClient.new(@urls, :filter_params => [:secret])
      client.instance_variable_get(:@filter_params).should == ["secret"]
    end

    ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY'].each do |proxy|
      context "when #{proxy} defined in environment" do
        after(:each) do
          ENV.delete(proxy)
        end

        it "initializes use of proxy" do
          ENV[proxy] = "https://my.proxy.com"
          client = RightScale::BalancedHttpClient.new(@urls)
          client.instance_variable_get(:@proxy_uri).to_s.should == "https://my.proxy.com"
        end

        it "infers http scheme for proxy address" do
          ENV[proxy] = "1.2.3.4"
          client = RightScale::BalancedHttpClient.new(@urls)
          client.instance_variable_get(:@proxy_uri).to_s.should == "http://1.2.3.4"
        end
      end
    end

    it "creates request balancer with health checker" do
      flexmock(RightSupport::Net::RequestBalancer).should_receive(:new).
          with(@urls, hsh(:policy => RightSupport::Net::LB::HealthCheck)).and_return(@balancer).once
      RightScale::BalancedHttpClient.new(@urls)
    end

    it "accepts comma-separated list of URLs" do
      flexmock(RightSupport::Net::RequestBalancer).should_receive(:new).
          with(on { |arg| arg.should == ["url1", "url2"] }, Hash).and_return(@balancer).once
      RightScale::BalancedHttpClient.new("url1, url2")
    end
  end

  context :check_health do
    before(:each) do
      @urls = ["http://my0.com", @url]
      @client = RightScale::BalancedHttpClient.new(@urls)
      @health_check_proc = @client.instance_variable_get(:@health_check_proc)
    end

    it "calls health check proc using first URL" do
      flexmock(@health_check_proc).should_receive(:call).with("http://my0.com").once
      @client.check_health
    end

    it "calls health check proc using specified URL" do
      flexmock(@health_check_proc).should_receive(:call).with("http://my1.com/api").once
      @client.check_health("http://my1.com/api")
    end

    it "returns result of health check" do
      flexmock(@health_check_proc).should_receive(:call).with("http://my0.com").and_return("ok").once
      @client.check_health.should == "ok"
    end

    RightScale::BalancedHttpClient::RETRY_STATUS_CODES.each do |code|
      it "raises NotResponding for #{code}" do
        flexmock(@health_check_proc).should_receive(:call).and_raise(RightScale::HttpExceptions.create(code))
        lambda { @client.check_health("http://my1.com") }.should raise_error(RightScale::BalancedHttpClient::NotResponding)
      end
    end
  end

  context :request do
    before(:each) do
      @params = {}
      @options = {}
      @result = {"out" => 123}
      @body = JSON.dump({:out => 123})
      @headers = {:status => "200 OK"}
      @response = [@result, 200, @body, @headers]
      @balancer.should_receive(:request).and_yield(@url).and_return(@response).by_default
      flexmock(RightSupport::Data::UUID).should_receive(:generate).and_return("random uuid").by_default
      @client = RightScale::BalancedHttpClient.new(@urls)
      flexmock(@client).should_receive(:blocking_request).and_return(@response).by_default
    end

    it "uses specified request UUID" do
      @log.should_receive(:info).with("Requesting POST <my uuid> /foo/bar").once
      @log.should_receive(:info).with("Completed <my uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes")
      @client.request(:post, @path, @params, :request_uuid => "my uuid")
    end

    it "generates request UUID if none specified" do
      @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar").once
      @log.should_receive(:info).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes").once
      @client.request(:post, @path)
    end

    it "logs request before sending it" do
      @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar").once
      @balancer.should_receive(:request).and_raise(RuntimeError).once
      @client.request(:post, @path) rescue nil
    end

    it "logs using specified log level" do
      @params = {:some => "data"}
      @log.should_receive(:debug).with("Requesting POST <random uuid> /foo/bar {:some=>\"data\"}").once
      @log.should_receive(:debug).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes | {\"out\"=>123}").once
      @client.request(:post, @path, @params, :log_level => :debug)
    end

    it "logs using configured log level if none specified" do
      @params = {:some => "data"}
      @log.should_receive(:level).and_return(:debug)
      @log.should_receive(:debug).with("Requesting POST <random uuid> /foo/bar {:some=>\"data\"}").once
      @log.should_receive(:debug).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes | {\"out\"=>123}").once
      @client.request(:post, @path, @params)
    end

    it "appends specified filter parameters to list" do
      @params = {:some => "data", :secret => "data", :other => "data"}
      @client = RightScale::BalancedHttpClient.new(@urls, :filter_params => [:secret])
      flexmock(@client).should_receive(:blocking_request).and_return(@response)
      @log.should_receive(:debug).with("Requesting POST <random uuid> /foo/bar {:some=>\"data\", :secret=>\"<hidden>\", :other=>\"<hidden>\"}").once
      @log.should_receive(:debug).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes | {\"out\"=>123}").once
      @client.request(:post, @path, @params, :log_level => :debug, :filter_params => [:other])
    end

    it "uses request balancer to make request" do
      flexmock(@client).should_receive(:blocking_request).with(:post, @path, @url, Hash, Hash, true).and_return(@response).once
      @balancer.should_receive(:request).and_yield(@url).and_return(@response).once
      @client.request(:post, @path)
    end

    it "removes user and password from host when logging" do
      flexmock(@client).should_receive(:log_success).with(@result, 200, @body, @headers, "http://my.com", @path, "random uuid", Time, :info).once
      @balancer.should_receive(:request).and_yield("http://111:secret@my.com").and_return(@response).once
      @client.request(:post, @path)
    end

    it "logs successful completion of request" do
      @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar")
      @log.should_receive(:info).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes").once
      @client.request(:post, @path, @params, @options)
    end

    it "returns result of request" do
      @client.request(:post, @path, @params, @options).should == @result
    end

    it "handles NoResult response from balancer" do
      no_result = RightSupport::Net::NoResult.new("no result", {})
      @log.should_receive(:error).with(/Failed <random uuid>.*#{@path}/).once
      @balancer.should_receive(:request).and_yield(@url).once
      flexmock(@client).should_receive(:blocking_request).and_raise(no_result).once
      flexmock(@client).should_receive(:handle_no_result).with(RightSupport::Net::NoResult, @url, Proc).and_yield(no_result).once
      @client.request(:get, @path)
    end

    it "converts RestClient exception to HttpException and raises it" do
      response = RightScale::Response.new({})
      bad_request = RestClient::Exceptions::EXCEPTIONS_MAP[400].new(nil, 400)
      @log.should_receive(:error).with(/Failed <random uuid>.*#{@path}/).once
      @balancer.should_receive(:request).and_yield(@url).once
      flexmock(@client).should_receive(:blocking_request).and_raise(bad_request).once
      lambda { @client.request(:get, @path) }.should raise_error(RightScale::HttpExceptions::BadRequest)
    end

    it "logs and re-raises unexpected exception" do
      @log.should_receive(:error).with(/Failed <random uuid>.*#{@path}/).once
      @balancer.should_receive(:request).and_raise(RuntimeError).once
      lambda { @client.request(:get, @path) }.should raise_error(RuntimeError)
    end
  end

  context :request_headers do
    before(:each) do
      @request_uuid = "my uuid"
      @options = {}
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "sets request uuid in header" do
      headers = @client.send(:request_headers, @request_uuid, @options)
      headers["X-Request-Lineage-Uuid"].should == "my uuid"
    end

    it "sets response to be JSON-encoded" do
      headers = @client.send(:request_headers, @request_uuid, @options)
      headers[:accept] == "application/json"
    end

    it "sets API version" do
      @client = RightScale::BalancedHttpClient.new(@urls, :api_version => "2.0")
      headers = @client.send(:request_headers, @request_uuid, @options)
      headers["X-API-Version"].should == "2.0"
    end

    it "does not set API version if not defined" do
      headers = @client.send(:request_headers, @request_uuid, @options)
      headers.has_key?("X-API-Version").should be false
    end

    it "sets any optionally specified headers" do
      @options = {:headers => {"Authorization" => "Bearer <session>"}}
      headers = @client.send(:request_headers, @request_uuid, @options)
      headers["Authorization"].should == "Bearer <session>"
    end

    it "sets debug option if in debug mode" do
      @log.should_receive(:level).and_return(:debug)
      headers = @client.send(:request_headers, @request_uuid, @options)
      headers["X-DEBUG"].should be true
    end
  end

  context :beautify_headers do
    before(:each) do
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "beautifies header keys" do
      headers = {"SERVER" => "nginx/1.4.2", "DATE" => "Tue, 25 Mar 2014 22:19:52 GMT",
                 "CONTENT_TYPE" => "application/json; charset=utf-8", "CONTENT_LENGTH" => "4", "CONNECTION" => "close",
                 "STATUS" => "200 OK", "CACHE_CONTROL" => "private, max-age=0, must-revalidate", "X_RUNTIME" => "1", "SET_COOKIE" => ""}
      result = @client.send(:beautify_headers, headers)
      result.should == {:server => "nginx/1.4.2", :date => "Tue, 25 Mar 2014 22:19:52 GMT",
                 :content_type => "application/json; charset=utf-8", :content_length => "4", :connection => "close",
                 :status => "200 OK", :cache_control => "private, max-age=0, must-revalidate", :x_runtime => "1", :set_cookie => ""}
    end

    it "converts hyphenations to underscores" do
      @client.send(:beautify_headers, {"NON-BLOCKING" => "yes"}).should == {:non_blocking => "yes"}
    end
  end

  context :blocking_init do
    after(:each) do
      ENV.delete("HTTPS_PROXY")
    end

    it "initializes use of proxy if defined" do
      ENV["HTTPS_PROXY"] = "https://my.proxy.com"
      flexmock(RestClient).should_receive(:proxy=).with("https://my.proxy.com").once
      RightScale::BalancedHttpClient.new(@urls)
    end

    it "returns proc" do
      @client = RightScale::BalancedHttpClient.new(@urls)
      @client.send(:blocking_init, {}).should be_a Proc
    end

    context "health check proc" do
      before(:each) do
        @http_client = flexmock("http client")
        flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_return(@http_client).by_default
      end

      it "removes user and password from URL when checking health" do
        @url = "http://111:secret@me.com"
        @client = RightScale::BalancedHttpClient.new(@url, :health_check_path => "/health-check")
        @http_client.should_receive(:get).with("http://me.com/health-check", Hash).once
        @client.instance_variable_get(:@health_check_proc).call(@url)
      end

      it "uses default path if none specified" do
        @client = RightScale::BalancedHttpClient.new(@url)
        @http_client.should_receive(:get).with("http://my.com/health-check", Hash).once
        @client.instance_variable_get(:@health_check_proc).call(@url)
      end

      it "appends health check path to any existing path" do
        @url = "http://my.com/foo"
        @client = RightScale::BalancedHttpClient.new(@url)
        @http_client.should_receive(:get).with("http://my.com/foo/health-check", Hash).once
        @client.instance_variable_get(:@health_check_proc).call(@url)
      end

      it "uses fixed timeout values" do
        @client = RightScale::BalancedHttpClient.new(@url, :open_timeout => 5, :request_timeout => 30)
        @http_client.should_receive(:get).with(String, {:open_timeout => 2, :timeout => 5}).once
        @client.instance_variable_get(:@health_check_proc).call(@url)
      end

      it "sets API version if specified" do
        @client = RightScale::BalancedHttpClient.new(@url, :api_version => "2.0")
        @http_client.should_receive(:get).with(String, hsh(:headers => {"X-API-Version" => "2.0"})).once
        @client.instance_variable_get(:@health_check_proc).call(@url)
      end
    end
  end

  context :non_blocking_init do
    after(:each) do
      ENV.delete("HTTPS_PROXY")
    end

    it "initializes use of proxy if defined" do
      ENV["HTTPS_PROXY"] = "https://my.proxy.com"
      client = RightScale::BalancedHttpClient.new(@urls, :non_blocking => true)
      client.instance_variable_get(:@proxy).should == {:host => "my.proxy.com", :port => 443}
    end

    it "applies user and password to proxy address if defined in proxy address" do
      ENV["HTTPS_PROXY"] = "https://111:secret@my.proxy.com"
      client = RightScale::BalancedHttpClient.new(@urls, :non_blocking => true)
      client.instance_variable_get(:@proxy).should == {:host => "my.proxy.com", :port => 443, :authorization => ["111", "secret"]}
    end

    it "returns health check proc" do
      @client = RightScale::BalancedHttpClient.new(@urls, :non_blocking => true)
      @client.send(:non_blocking_init, :non_blocking => true).should be_a Proc
    end

    context "health check proc" do
      it "removes user and password from URL when checking health" do
        @url = "http://111:secret@me.com"
        @client = RightScale::BalancedHttpClient.new(@url, :non_blocking => true, :health_check_path => "/health-check")
        flexmock(@client).should_receive(:non_blocking_request).with(:get, "", "http://me.com", Hash, {:path => "/health-check"}, false).once
        @client.instance_variable_get(:@health_check_proc).call(@url)
      end

      it "uses default path if none specified" do
        @client = RightScale::BalancedHttpClient.new(@urls, :non_blocking => true)
        flexmock(@client).should_receive(:non_blocking_request).with(:get, "", @host, Hash, {:path => "/health-check"}, false).once
        @client.instance_variable_get(:@health_check_proc).call(@url)
      end

      it "appends health check path to any existing path" do
        @url = "http://my.com/foo"
        @client = RightScale::BalancedHttpClient.new(@url, :non_blocking => true)
        flexmock(@client).should_receive(:non_blocking_request).with(:get, "", @host, Hash, {:path => "/foo/health-check"}, false).once
        @client.instance_variable_get(:@health_check_proc).call(@url)
      end

      it "uses fixed timeout values" do
        @client = RightScale::BalancedHttpClient.new(@url, :non_blocking => true, :open_timeout => 5, :request_timeout => 30)
        connect_options = {:connect_timeout => 2, :inactivity_timeout => 5}
        flexmock(@client).should_receive(:non_blocking_request).with(:get, "", @host, connect_options, Hash, false).once
        @client.instance_variable_get(:@health_check_proc).call(@url)
      end

      it "sets API version if specified" do
        @client = RightScale::BalancedHttpClient.new(@url, :non_blocking => true, :api_version => "2.0")
        request_options = {:path => "/health-check", :head => {"X-API-Version" => "2.0"}}
        flexmock(@client).should_receive(:non_blocking_request).with(:get, "", @host, Hash, request_options, false).once
        @client.instance_variable_get(:@health_check_proc).call(@url)
      end

      it "uses proxy if defined" do
        ENV["HTTPS_PROXY"] = "https://my.proxy.com"
        @client = RightScale::BalancedHttpClient.new(@url, :non_blocking => true)
        connect_options = {:connect_timeout => 2, :inactivity_timeout => 5, :proxy => {:host => "my.proxy.com", :port => 443}}
        flexmock(@client).should_receive(:non_blocking_request).with(:get, "", @host, connect_options, Hash, false).once
        @client.instance_variable_get(:@health_check_proc).call(@url)
      end
    end
  end

  context :blocking_options do
    before(:each) do
      @params = {}
      @headers = {}
      @options = {}
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "sets default open and request timeouts" do
      connect_options, request_options = @client.send(:blocking_options, :get, @path, @params, @headers, @options)
      connect_options.should == {}
      request_options[:open_timeout].should == RightScale::BalancedHttpClient::DEFAULT_OPEN_TIMEOUT
      request_options[:timeout].should == RightScale::BalancedHttpClient::DEFAULT_REQUEST_TIMEOUT
    end

    it "sets specified open and request timeouts" do
      @options = {:open_timeout => 1, :request_timeout => 2}
      _, request_options = @client.send(:blocking_options, @verb, :get, @params, @headers, @options)
      request_options[:open_timeout].should == 1
      request_options[:timeout].should == 2
    end

    it "sets request headers" do
      @headers = {:some => "header"}
      _, request_options = @client.send(:blocking_options, :get, @path, @params, @headers, @options)
      request_options[:headers].should == @headers
    end

    [:get, :delete].each do |verb|
      context "with #{verb.inspect}" do
        it "uses form-encoded query option for parameters" do
          @params = {:some => "data"}
          _, request_options = @client.send(:blocking_options, verb, @path, @params, @headers, @options)
          request_options[:query].should == @params
          request_options[:payload].should be nil
        end

        it "omits query option if there are no parameters" do
          _, request_options = @client.send(:blocking_options, verb, @path, @params, @headers, @options)
          request_options.has_key?(:query).should be false
        end
      end
    end

    [:post, :put].each do |verb|
      context "with #{verb.inspect}" do
        it "uses JSON-encoded payload options for parameters" do
          @params = {:some => "data"}
          _, request_options = @client.send(:blocking_options, verb, @path, @params, @headers, @options)
          request_options[:query].should be_nil
          request_options[:payload].should == JSON.dump(@params)
          request_options[:headers][:content_type].should == "application/json"
        end
      end
    end
  end

  context :non_blocking_options do
    before(:each) do
      @params = {}
      @headers = {}
      @options = {}
      @client = RightScale::BalancedHttpClient.new(@urls, :non_blocking => true)
    end

    it "sets default open and request timeouts" do
      connect_options, _ = @client.send(:non_blocking_options, :get, @path, @params, @headers, @options)
      connect_options[:connect_timeout].should == RightScale::BalancedHttpClient::DEFAULT_OPEN_TIMEOUT
      connect_options[:inactivity_timeout].should == RightScale::BalancedHttpClient::DEFAULT_REQUEST_TIMEOUT
    end

    it "sets specified open and request timeouts" do
      @options = {:open_timeout => 1, :request_timeout => 2}
      connect_options, _ = @client.send(:non_blocking_options, @verb, :get, @params, @headers, @options)
      connect_options[:connect_timeout].should == 1
      connect_options[:inactivity_timeout].should == 2
    end

    it "sets request headers" do
      @headers = {:some => "header"}
      _, request_options = @client.send(:non_blocking_options, :get, @path, @params, @headers, @options)
      request_options[:head].should == @headers
    end

    it "sets proxy if defined" do
      ENV["HTTPS_PROXY"] = "https://my.proxy.com"
      @client = RightScale::BalancedHttpClient.new(@url, :non_blocking => true)
      connect_options, _ = @client.send(:non_blocking_options, :get, @path, @params, @headers, @options)
      connect_options[:proxy].should == {:host => "my.proxy.com", :port => 443}
    end

    [:get, :delete].each do |verb|
      context "with #{verb.inspect}" do
        it "appends form-encoded query option to path" do
          @params = {:some => "data"}
          _, request_options = @client.send(:non_blocking_options, verb, @path, @params, @headers, @options)
          request_options[:path].should == "/foo/bar?some=data"
          request_options[:body].should be nil
        end
      end
    end

    [:post, :put].each do |verb|
      context "with #{verb.inspect}" do
        it "stores JSON-encoded parameters in body" do
          @params = {:some => "data"}
          _, request_options = @client.send(:non_blocking_options, verb, @path, @params, @headers, @options)
          request_options[:path].should == @path
          request_options[:body].should == JSON.dump(@params)
          request_options[:head][:content_type].should == "application/json"
        end
      end
    end
  end

  context :blocking_request do
    before(:each) do
      @connect_options = {}
      @request_options = {:open_timeout => 2, :request_timeout => 5}
      @result = {"out" => 123}
      @body = JSON.dump({:out => 123})
      @headers = {:status => "200 OK"}
      @response = flexmock("response", :code => 200, :body => @body, :headers => @headers).by_default
      @http_client = flexmock("http client")
      flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_return(@http_client).by_default
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "makes request" do
      @http_client.should_receive(:get).with(@host + @path, @request_options).and_return(@response).once
      @client.send(:blocking_request, :get, @path, @host, @connect_options, @request_options, true)
    end

    it "processes response and returns result plus response code, body, and headers" do
      @http_client.should_receive(:get).with(@host + @path, @request_options).and_return(@response).once
      result = @client.send(:blocking_request, :get, @path, @host, @connect_options, @request_options, true)
      result.should == [@result, 200, @body, @headers]
    end

    it "returns nil if response is nil" do
      @http_client.should_receive(:get).with(@host + @path, @request_options).and_return(nil).once
      result = @client.send(:blocking_request, :get, @path, @host, @connect_options, @request_options, true)
      result.should == [nil, nil, nil, nil]
    end
  end

  context :non_blocking_request do
    before(:each) do
      @connect_options = {:connect_timeout => 2, :inactivity_timeout => 5}
      @request_options = {:path => @path}
      @result = {"out" => 123}
      @body = JSON.dump({:out => 123})
      @headers = EventMachine::HttpResponseHeader.new
      @headers.http_status = 200
      @response = flexmock("em http response", :response_header => @headers, :response => @body,
                                :error => nil, :errback => true, :callback => true).by_default
      @request = flexmock("em http request", :get => @response).by_default
      flexmock(EM::HttpRequest).should_receive(:new).and_return(@request).by_default
      @fiber = flexmock("fiber", :resume => true).by_default
      flexmock(Fiber).should_receive(:current).and_return(@fiber)
      flexmock(Fiber).should_receive(:yield).and_return([200, @body, @headers]).by_default
      @client = RightScale::BalancedHttpClient.new(@urls, :non_blocking => true)
    end

    it "makes request" do
      @response.should_receive(:callback).and_yield.once
      @fiber.should_receive(:resume).with(200, @body, @headers).once
      flexmock(EM::HttpRequest).should_receive(:new).with(@host, @connect_options).and_return(@request).once
      @request.should_receive(:get).with(@request_options).and_return(@response).once
      @client.send(:non_blocking_request, :get, @path, @host, @connect_options, @request_options, true)
    end

    it "processes response and returns result plus response code, body, and headers" do
      @response.should_receive(:callback).and_yield.once
      @fiber.should_receive(:resume).with(200, @body, @headers).once
      flexmock(EM::HttpRequest).should_receive(:new).with(@host, @connect_options).and_return(@request).once
      @request.should_receive(:get).with(@request_options).and_return(@response).once
      result = @client.send(:non_blocking_request, :get, @path, @host, @connect_options, @request_options, true)
      result.should == [@result, 200, @body, @headers]
    end

    it "converts Errno::ETIMEDOUT error to 504" do
      @headers.http_status = 504
      @response.should_receive(:errback).and_yield.once
      @response.should_receive(:error).and_return("Errno::ETIMEDOUT")
      @fiber.should_receive(:resume).with(504, "Errno::ETIMEDOUT").once
      flexmock(Fiber).should_receive(:yield).and_return([504, "Errno::ETIMEDOUT"]).once
      flexmock(EM::HttpRequest).should_receive(:new).with(@host, @connect_options).and_return(@request).once
      @request.should_receive(:get).and_return(@response).once
      lambda { @client.send(:non_blocking_request, :get, @path, @host, @connect_options, @request_options, true) }.
          should raise_error(RightScale::HttpExceptions::GatewayTimeout)
    end
  end

  context :process_response do
    before(:each) do
      @result = {"out" => 123}
      @body = JSON.dump({:out => 123})
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "returns location header for 201 response" do
      @client.send(:process_response, 201, "", {:status => "201 Created", :location => "/href"}).should == "/href"
    end

    it "returns body without decoding by default" do
      @client.send(:process_response, 200, @body, {:status => "200 OK"}).should == @body
    end

    it "returns JSON decoded response if decoding requested" do
      @client.send(:process_response, 200, @body, {:status => "200 OK"}, true).should == @result
    end

    it "returns nil if JSON decoded response is empty" do
      @client.send(:process_response, 200, "null", {:status => "200 OK"}, true).should be nil
    end

    it "returns nil if response is empty" do
      @client.send(:process_response, 204, nil, {:status => "204 No Content"}).should be nil
    end

    it "returns nil if response is nil" do
      @client.send(:process_response, 200, nil, {:status => "200 OK"}).should be nil
    end

    it "returns nil if body is empty" do
      @client.send(:process_response, 200, "", {:status => "200 OK"}).should be nil
    end

    it "raises exception if response code indicates failure" do
      lambda { @client.send(:process_response, 400, nil, {:status => "400 Bad Request"}) }.should raise_error(RightScale::HttpExceptions::BadRequest)
    end
  end

  context :handle_no_result do
    before(:each) do
      @no_result = RightSupport::Net::NoResult.new("no result", {})
      @client = RightScale::BalancedHttpClient.new(@urls)
      @yielded = nil
      @proc = lambda { |e| @yielded = e }
    end

    it "uses configured server name" do
      @client = RightScale::BalancedHttpClient.new(@urls, :server_name => "Some server")
      lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should \
        raise_error(RightScale::BalancedHttpClient::NotResponding, "Some server not responding")
    end

    it "defaults server name to host name" do
      lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should \
        raise_error(RightScale::BalancedHttpClient::NotResponding, "http://my.com not responding")
    end

    it "uses last exception stored in NoResult details" do
      gateway_timeout = RightScale::HttpExceptions.create(504, "server timeout")
      bad_request = RightScale::HttpExceptions.create(400, "bad data")
      @no_result = RightSupport::Net::NoResult.new("no result", {@url => gateway_timeout, @url => bad_request})
      lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should raise_error(bad_request)
      @yielded.should == bad_request
    end

    it "uses server name in NotResponding exception if there are no details" do
      lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should \
        raise_error(RightScale::BalancedHttpClient::NotResponding, "http://my.com not responding")
      @yielded.should == @no_result
    end

    it "uses http_body in raised NotResponding exception if status code is 504" do
      gateway_timeout = RightScale::HttpExceptions.create(504, "server timeout")
      @no_result = RightSupport::Net::NoResult.new("no result", {@url => gateway_timeout})
      lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should \
        raise_error(RightScale::BalancedHttpClient::NotResponding, "server timeout")
      @yielded.should == gateway_timeout
    end

    it "uses raise NotResponding if status code is 504 and http_body is nil or empty" do
      gateway_timeout = RightScale::HttpExceptions.create(504, "")
      @no_result = RightSupport::Net::NoResult.new("no result", {@url => gateway_timeout})
      lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should \
        raise_error(RightScale::BalancedHttpClient::NotResponding, "http://my.com not responding")
      @yielded.should == gateway_timeout
    end

    [502, 503].each do |code|
      it "uses server name in NotResponding exception if status code is #{code}" do
        e = RightScale::HttpExceptions.create(code)
        @no_result = RightSupport::Net::NoResult.new("no result", {@url => e})
        lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should \
          raise_error(RightScale::BalancedHttpClient::NotResponding, "http://my.com not responding")
      end
    end

    it "raises last exception in details if not retryable" do
      bad_request = RightScale::HttpExceptions.create(400, "bad data")
      @no_result = RightSupport::Net::NoResult.new("no result", {@url => bad_request})
      lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should raise_error(bad_request)
      @yielded.should == bad_request
    end
  end

  context :log_success do
    before(:each) do
      @result = {"out" => 123}
      @body = JSON.dump({:out => 123})
      @headers = {:status => "200 OK"}
      @response = [@result, 200, @body, @headers]
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "logs response length using header :content_length if available" do
      @headers.merge!(:content_length => 99)
      @log.should_receive(:info).with("Completed <uuid> in 10ms | 200 [http://my.com/foo/bar] | 99 bytes").once
      @client.send(:log_success, @result, 200, @body, @headers, "http://my.com", @path, "uuid", @now, :info).should be true
    end

    it "logs response length using response body size of :content_lenght not available" do
      @log.should_receive(:info).with("Completed <uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes").once
      @client.send(:log_success, @result, 200, @body, @headers, "http://my.com", @path, "uuid", @now, :info).should be true
    end

    it "logs duration based on request start time" do
      @log.should_receive(:info).with("Completed <uuid> in 20ms | 200 [http://my.com/foo/bar] | 11 bytes").once
      @client.send(:log_success, @result, 200, @body, @headers, "http://my.com", @path, "uuid", @now - 0.01, :info).should be true
    end

    it "log result if log level option set to :debug" do
      @log.should_receive(:debug).with("Completed <uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes | {\"out\"=>123}").once
      @client.send(:log_success, @result, 200, @body, @headers, "http://my.com", @path, "uuid", @now, :debug).should be true
    end
  end

  context :log_failure do
    before(:each) do
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "logs exception" do
      exception = RightScale::HttpExceptions.create(400, "bad data")
      @log.should_receive(:error).with("Failed <uuid> in 10ms | 400 [http://my.com/foo/bar \"params\"] | 400 Bad Request: bad data").once
      @client.send(:log_failure, @url, @path, "params", [], "uuid", @now, :info, exception).should be true
    end

    it "logs error string" do
      @log.should_receive(:error).with("Failed <uuid> in 10ms | nil [http://my.com/foo/bar \"params\"] | bad data").once
      @client.send(:log_failure, @url, @path, "params", [], "uuid", @now, :info, "bad data").should be true
    end

    it "filters parameters" do
      @log.should_receive(:error).with("Failed <uuid> in 10ms | nil [http://my.com/foo/bar {:secret=>\"<hidden>\"}] | bad data").once
      @client.send(:log_failure, @url, @path, {:secret => "data"}, ["secret"], "uuid", @now, :info, "bad data").should be true
    end
  end

  context :log_text do
    before(:each) do
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    context "when no exception" do

      context "in info mode with no host" do
        it "generates text containing path" do
          text = @client.send(:log_text, @path, {:value => 123}, [], :info)
          text.should == "/foo/bar"
        end
      end

      context "in info mode with host" do
        it "generates text containing host and path" do
          text = @client.send(:log_text, @path, {:value => 123}, [], :info, @url)
          text.should == "[http://my.com/foo/bar]"
        end
      end

      context "and in debug mode" do
        it "generates text containing containing host, path, and filtered parameters" do
          text = @client.send(:log_text, @path, {:some => "data", :secret => "data"}, ["secret"], :debug, @url)
          text.should == "[http://my.com/foo/bar {:some=>\"data\", :secret=>\"<hidden>\"}]"
        end
      end
    end

    context "when exception" do
      it "includes params regardless of mode" do
        text = @client.send(:log_text, @path, {:some => "data", :secret => "data"}, ["secret"], :info, @url, "failed")
        text.should == "[http://my.com/foo/bar {:some=>\"data\", :secret=>\"<hidden>\"}] | failed"
      end

      it "includes exception text" do
        exception = RightScale::HttpExceptions.create(400, "bad data")
        text = @client.send(:log_text, @path, {:some => "data", :secret => "data"}, ["secret"], :info, @url, exception)
        text.should == "[http://my.com/foo/bar {:some=>\"data\", :secret=>\"<hidden>\"}] | 400 Bad Request: bad data"
      end
    end
  end

  context :filter do
    before(:each) do
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "applies filters" do
      filter = ["secret"]
      params = {:some => 1, "secret" => "data"}
      @client.send(:filter, params, filter).should == {:some => 1, "secret" => "<hidden>"}
    end

    it "converts parameter names to string before comparing to filter list" do
      filter = ["secret", "very secret"]
      params = {:some => 1, :secret => "data", "very secret" => "data"}
      @client.send(:filter, params, filter).should == {:some => 1, :secret => "<hidden>", "very secret" => "<hidden>"}
    end

    it "does not filter if no filters are specified" do
      params = {:some => 1, "secret" => "data"}
      @client.send(:filter, params, []).should == params
    end

    it "does not filter if params is not a hash" do
      @client.send(:filter, "params", ["secret"]).should == "params"
    end
  end

  context :format do

    before(:each) do
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "converts param to key=value format" do
      @client.send(:format, {:foo => "bar"}).should == "foo=bar"
    end

    it "escapes param value" do
      @client.send(:format, {:path => "/foo/bar"}).should == "path=%2Ffoo%2Fbar"
    end

    it "breaks arrays into multiple params" do
      params = {:paths => ["/foo/bar", "/foo/bar2"]}
      @client.send(:format, params).should == "paths[]=%2Ffoo%2Fbar&paths[]=%2Ffoo%2Fbar2"
    end

    it "separates params with '&'" do
      params = {:foo => 111, :paths => ["/foo/bar", "/foo/bar2"], :bar => 999}
      response = @client.send(:format, params)
      response.split("&").sort.should == ["bar=999", "foo=111", "paths[]=%2Ffoo%2Fbar", "paths[]=%2Ffoo%2Fbar2"]
    end
  end

  context :split do
    before(:each) do
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "leaves array as an array" do
      @client.send(:split, ["data"]).should == ["data"]
    end

    it "turns nil into an empty array" do
      @client.send(:split, nil).should == []
    end

    it "splits a string using default pattern" do
      @client.send(:split, "some,data").should == ["some", "data"]
    end

    it "splits a string using specified pattern" do
      @client.send(:split, "some#data", /#/).should == ["some", "data"]
    end
  end

  context :exception_text do
    context "when string exception" do
      it "adds exception text" do
        RightScale::BalancedHttpClient.exception_text("failed").should == "failed"
      end
    end

    context "when REST exception" do
      it "adds exception code/type and any http_body" do
        exception = RightScale::HttpExceptions.create(400, "bad data")
        RightScale::BalancedHttpClient.exception_text(exception).should == "400 Bad Request: bad data"
      end

      it "adds exception code/type but omits http_body if it is html" do
        exception = RightScale::HttpExceptions.create(400, "<html> bad </html>")
        RightScale::BalancedHttpClient.exception_text(exception).should == "400 Bad Request"
      end

      it "adds exception code/type and omits http_body if it is blank" do
        exception = RightScale::HttpExceptions.create(400, "")
        RightScale::BalancedHttpClient.exception_text(exception).should == "400 Bad Request"
      end
    end

    context "when NoResult exception" do
      it "adds exception class and message" do
        exception = RightSupport::Net::NoResult.new("no result")
        RightScale::BalancedHttpClient.exception_text(exception).should == "RightSupport::Net::NoResult: no result"
      end
    end

    context "when non-REST, non-NoResult exception" do
      it "adds exception class and message" do
        exception = ArgumentError.new("bad arg")
        RightScale::BalancedHttpClient.exception_text(exception).should == "ArgumentError: bad arg"
      end
    end

    context "when non-REST, non-NoResult exception with backtrace" do
      it "adds exception class, message, and backtrace" do
        exception = ArgumentError.new("bad arg")
        flexmock(exception).should_receive(:backtrace).and_return(["line 1", "line 2"])
        RightScale::BalancedHttpClient.exception_text(exception).should == "ArgumentError: bad arg in\nline 1\nline 2"
      end
    end
  end
end
