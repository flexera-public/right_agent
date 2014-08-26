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
    @options = {}
    @url = "http://my.com"
    @urls = [@url]
    @host = @url
    @path = "/foo/bar"
    @balancer = flexmock("balancer")
    flexmock(RightSupport::Net::RequestBalancer).should_receive(:new).and_return(@balancer).by_default
    @later = (@now = Time.now)
    @tick = 0.01
    flexmock(Time).should_receive(:now).and_return { @later += @tick }
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

    it "creates blocking HTTP client" do
      client = RightScale::BalancedHttpClient.new(@urls)
      client.instance_variable_get(:@http_client).should be_a RightScale::BlockingClient
    end

    it "creates non-blocking HTTP client if specified" do
      client = RightScale::BalancedHttpClient.new(@urls, :non_blocking => true)
      client.instance_variable_get(:@http_client).should be_a RightScale::NonBlockingClient
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
      @health_check_proc = @client.instance_variable_get(:@http_client).health_check_proc
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
      @result = {"out" => 123}
      @body = JSON.dump({:out => 123})
      @headers = {:status => "200 OK"}
      @response = [@result, 200, @body, @headers]
      @balancer.should_receive(:request).and_yield(@url).and_return(@response).by_default
      flexmock(RightSupport::Data::UUID).should_receive(:generate).and_return("random uuid").by_default
      @client = RightScale::BalancedHttpClient.new(@urls, :filter_params => [:secret])
      @http_client = @client.instance_variable_get(:@http_client)
      flexmock(@http_client).should_receive(:request).and_return(@response).by_default
    end

    it "uses specified request UUID" do
      @log.should_receive(:info).with("Requesting POST <my uuid> /foo/bar {}").once
      @log.should_receive(:info).with("Completed <my uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes")
      @client.request(:post, @path, @params, :request_uuid => "my uuid")
    end

    it "generates request UUID if none specified" do
      @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar {}").once
      @log.should_receive(:info).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes").once
      @client.request(:post, @path)
    end

    it "logs request before sending it" do
      @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar {}").once
      flexmock(@http_client).should_receive(:request).and_raise(RuntimeError).once
      @client.request(:post, @path) rescue nil
    end

    it "logs using specified :log_level" do
      @params = {:some => "data"}
      @log.should_receive(:debug).with("Requesting POST <random uuid> /foo/bar {:some=>\"data\"}").once
      @log.should_receive(:debug).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes").once
      @client.request(:post, @path, @params, :log_level => :debug)
    end

    it "logs using :info level by default" do
      @params = {:some => "data"}
      @log.should_receive(:level).and_return(:debug)
      @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar {:some=>\"data\"}").once
      @log.should_receive(:info).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes | {\"out\"=>123}").once
      @client.request(:post, @path, @params)
    end

    it "appends specified filter parameters to list when Log.level is :debug" do
      @params = {:some => "data", :secret => "data", :other => "data"}
      @log.should_receive(:level).and_return(:debug)
      @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar {:some=>\"data\", :secret=>\"<hidden>\", :other=>\"<hidden>\"}").once
      @log.should_receive(:info).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes | {\"out\"=>123}").once
      @client.request(:post, @path, @params, :filter_params => [:other])
    end

    it "removes user and password from host when logging" do
      flexmock(@client).should_receive(:log_success).with(@result, 200, @body, @headers, "http://my.com", @path, "random uuid", Time, :info).once
      @balancer.should_receive(:request).and_yield("http://111:secret@my.com").and_return(@response).once
      @client.request(:post, @path)
    end

    it "logs successful completion of request" do
      @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar {}")
      @log.should_receive(:info).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes").once
      @client.request(:post, @path, @params, @options)
    end

    it "returns result of request" do
      @client.request(:post, @path, @params, @options).should == @result
    end

    it "handles poll requests separately" do
      flexmock(@client).should_receive(:poll_request).and_return(@response).once
      flexmock(@client).should_receive(:rest_request).and_return(@response).never
      @client.request(:poll, @path, @params, @options).should == @result
    end

    it "handles NoResult response from balancer" do
      no_result = RightSupport::Net::NoResult.new("no result", {})
      @log.should_receive(:error).with(/Failed <random uuid>.*#{@path}/).once
      @balancer.should_receive(:request).and_yield(@url).once
      flexmock(@http_client).should_receive(:request).and_raise(no_result).once
      flexmock(@client).should_receive(:handle_no_result).with(RightSupport::Net::NoResult, @url, Proc).and_yield(no_result).once
      @client.request(:get, @path)
    end

    it "converts RestClient exception to HttpException and raises it" do
      bad_request = RestClient::Exceptions::EXCEPTIONS_MAP[400].new(nil, 400)
      @log.should_receive(:error).with(/Failed <random uuid>.*#{@path}/).once
      flexmock(@http_client).should_receive(:request).and_raise(bad_request).once
      lambda { @client.request(:get, @path) }.should raise_error(RightScale::HttpExceptions::BadRequest)
    end

    it "logs and re-raises unexpected exception" do
      @log.should_receive(:error).with(/Failed <random uuid>.*#{@path}/).once
      flexmock(@http_client).should_receive(:request).and_raise(RuntimeError).once
      lambda { @client.request(:get, @path) }.should raise_error(RuntimeError)
    end

    it "passes back host used with user and password removed" do
      flexmock(@client).should_receive(:log_success).with(@result, 200, @body, @headers, "http://my.com", @path, "random uuid", Time, :info).once
      @balancer.should_receive(:request).and_yield("http://111:secret@my.com").and_return(@response).once
      @client.request(:post, @path)
    end
  end

  context :close do
    before(:each) do
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "closes HTTP client" do
      flexmock(@client.instance_variable_get(:@http_client)).should_receive(:close).with("terminating").once
      @client.close("terminating").should be true
    end

    it "does nothing if there is no HTTP client" do
      @client.instance_variable_set(:@http_client, nil)
      @client.close("terminating").should be true
    end
  end

  context :request_headers do
    before(:each) do
      @request_uuid = "my uuid"
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

  context "requesting" do
    before(:each) do
      @tick = 1
      @used = {}
      @result = {"out" => 123}
      @body = JSON.dump({:out => 123})
      @headers = {:status => "200 OK"}
      @response = [@result, 200, @body, @headers]
      @balancer.should_receive(:request).and_yield(@url).and_return(@response).by_default
      @client = RightScale::BalancedHttpClient.new(@urls)
      @http_client = @client.instance_variable_get(:@http_client)
      flexmock(@http_client).should_receive(:request).and_return(@response).by_default
      @connect_options = {}
      @request_options = {:open_timeout => 2, :request_timeout => 5}
    end

    context :rest_request do
      it "make requests using request balancer" do
        flexmock(@http_client).should_receive(:request).with(:post, @path, @url, Hash, Hash).and_return(@response).once
        @balancer.should_receive(:request).and_yield(@url).once
        @client.send(:rest_request, :post, @path, @connect_options, @request_options, @used)
      end

      it "uses request balancer to make request" do
        flexmock(@http_client).should_receive(:request).with(:post, @path, @url, Hash, Hash).and_return(@response).once
        @balancer.should_receive(:request).and_yield(@url).and_return(@response).once
        @client.send(:rest_request, :post, @path, @connect_options, @request_options, @used)
      end

      it "passes back host used with user and password removed" do
        @balancer.should_receive(:request).and_yield("http://111:secret@my.com").and_return(@response).once
        @client.send(:rest_request, :post, @path, @connect_options, @request_options, @used)
        @used[:host].should == "http://my.com"
      end

      it "returns result and response info" do
        @balancer.should_receive(:request).and_yield(@url).and_return(@response).once
        @client.send(:rest_request, :post, @path, @connect_options, @request_options, @used).should == @response
      end
    end

    context :poll_request do
      before(:each) do
        @started_at = @now
        @request_timeout = 30
        @stop_at = @started_at + @request_timeout
        @connection = {:host => @host, :expires_at => @later + 5}
      end

      it "makes get request if there is no existing connection" do
        @http_client.instance_variable_get(:@connections)[@path].should be nil
        flexmock(@http_client).should_receive(:request).with(:get, @path, @url, Hash, Hash).and_return(@response).once
        @client.send(:poll_request, @path, @connect_options, @request_options, @request_timeout, @started_at, @used)
      end

      it "makes get request if there is connection but it has expired" do
        @connection = {:host => @host, :expires_at => @now}
        @http_client.instance_variable_get(:@connections)[@path] = @connection
        flexmock(@http_client).should_receive(:request).with(:get, @path, @url, Hash, Hash).and_return(@response).once
        @client.send(:poll_request, @path, @connect_options, @request_options, @request_timeout, @started_at, @used)
      end

      it "returns after get request if request has timed out" do
        @response = [nil, 200, nil, @headers]
        @balancer.should_receive(:request).and_return(@response).once
        @client.send(:poll_request, @path, @connect_options, @request_options, 1, @started_at, @used).should == @response
      end

      it "makes poll request after get request if result is nil and there is an unexpired connection" do
        get_response = [nil, 200, nil, @headers]
        @balancer.should_receive(:request).and_return do
          @http_client.instance_variable_get(:@connections)[@path] = @connection
          get_response
        end.once
        flexmock(@http_client).should_receive(:poll).with(@connection, @request_options, @stop_at).and_return(@response).once
        @client.send(:poll_request, @path, @connect_options, @request_options, @request_timeout, @started_at, @used).should == @response
      end

      it "makes poll request without get request if there is an unexpired connection" do
        @connection[:expires_at] = @later + 10
        @http_client.instance_variable_get(:@connections)[@path] = @connection
        flexmock(@http_client).should_receive(:poll).with(@connection, @request_options, @stop_at).and_return(@response).once
        flexmock(@http_client).should_receive(:request).never
        @client.send(:poll_request, @path, @connect_options, @request_options, @request_timeout, @started_at, @used).should == @response
      end

      it "returns result and response info" do
        @balancer.should_receive(:request).and_yield(@url).and_return(@response).once
        @client.send(:poll_request, @path, @connect_options, @request_options, @request_timeout, @started_at, @used).should == @response
      end

      it "passes back host used" do
        @balancer.should_receive(:request).and_yield("http://111:secret@my.com").and_return(@response).once
        @client.send(:poll_request, @path, @connect_options, @request_options, @request_timeout, @started_at, @used)
        @used[:host].should == "http://my.com"
      end

      it "converts retryable exceptions to NotResponding for poll requests" do
        bad_gateway = RightScale::HttpExceptions.create(502)
        @connection[:expires_at] = @later + 10
        @http_client.instance_variable_get(:@connections)[@path] = @connection
        flexmock(@http_client).should_receive(:poll).with(@connection, @request_options, @stop_at).and_raise(bad_gateway).once
        lambda do
          @client.send(:poll_request, @path, @connect_options, @request_options, @request_timeout, @started_at, @used).should == @response
        end.should raise_error(RightScale::BalancedHttpClient::NotResponding)
      end

      it "converts RequestTimeout without a status code to NotResponding for poll requests" do
        request_timeout = RestClient::Exceptions::EXCEPTIONS_MAP[408].new
        @connection[:expires_at] = @later + 10
        @http_client.instance_variable_get(:@connections)[@path] = @connection
        flexmock(@http_client).should_receive(:poll).with(@connection, @request_options, @stop_at).and_raise(request_timeout).once
        lambda do
          @client.send(:poll_request, @path, @connect_options, @request_options, @request_timeout, @started_at, @used).should == @response
        end.should raise_error(RightScale::BalancedHttpClient::NotResponding, "Request timeout")
      end
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
      lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.
          should raise_error(RightScale::HttpExceptions::BadRequest)
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

    it "raises NotResponding if status code is 504 and http_body is nil or empty" do
      gateway_timeout = RightScale::HttpExceptions.create(504, "")
      @no_result = RightSupport::Net::NoResult.new("no result", {@url => gateway_timeout})
      lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should \
        raise_error(RightScale::BalancedHttpClient::NotResponding, "http://my.com not responding")
      @yielded.should == gateway_timeout
    end

    [408, 502, 503].each do |code|
      it "uses server name in NotResponding exception if status code is #{code}" do
        e = RightScale::HttpExceptions.create(code)
        @no_result = RightSupport::Net::NoResult.new("no result", {@url => e})
        lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should \
          raise_error(RightScale::BalancedHttpClient::NotResponding, "http://my.com not responding")
      end
    end

    it "raises NotResponding for RequestTimeout even if exception has no status code" do
      request_timeout = RestClient::Exceptions::EXCEPTIONS_MAP[408].new
      @no_result = RightSupport::Net::NoResult.new("no result", {@url => request_timeout})
      lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should \
        raise_error(RightScale::BalancedHttpClient::NotResponding, "Request timeout")
      @yielded.should == request_timeout
    end

    it "raises last exception in details if not retryable" do
      bad_request = RightScale::HttpExceptions.create(400, "bad data")
      @no_result = RightSupport::Net::NoResult.new("no result", {@url => bad_request})
      lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.
          should raise_error(RightScale::HttpExceptions::BadRequest)
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

    it "logs response length using response body size of :content_length not available" do
      @log.should_receive(:info).with("Completed <uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes").once
      @client.send(:log_success, @result, 200, @body, @headers, "http://my.com", @path, "uuid", @now, :info).should be true
    end

    it "logs duration based on request start time" do
      @log.should_receive(:info).with("Completed <uuid> in 20ms | 200 [http://my.com/foo/bar] | 11 bytes").once
      @client.send(:log_success, @result, 200, @body, @headers, "http://my.com", @path, "uuid", @now - 0.01, :info).should be true
    end

    it "log result if Log.level is set to :debug" do
      @log.should_receive(:level).and_return(:debug)
      @log.should_receive(:info).with("Completed <uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes | {\"out\"=>123}").once
      @client.send(:log_success, @result, 200, @body, @headers, "http://my.com", @path, "uuid", @now, :info).should be true
    end

    it "logs using the specified log_level" do
      @log.should_receive(:debug).once
      @client.send(:log_success, @result, 200, @body, @headers, "http://my.com", @path, "uuid", @now, :debug)
    end
  end

  context :log_failure do
    before(:each) do
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "logs exception" do
      exception = RightScale::HttpExceptions.create(400, "bad data")
      @log.should_receive(:error).with("Failed <uuid> in 10ms | 400 [http://my.com/foo/bar \"params\"] | 400 Bad Request: bad data").once
      @client.send(:log_failure, @url, @path, "params", [], "uuid", @now, exception).should be true
    end

    it "logs error string" do
      @log.should_receive(:error).with("Failed <uuid> in 10ms | nil [http://my.com/foo/bar \"params\"] | bad data").once
      @client.send(:log_failure, @url, @path, "params", [], "uuid", @now, "bad data").should be true
    end

    it "filters parameters" do
      @log.should_receive(:error).with("Failed <uuid> in 10ms | nil [http://my.com/foo/bar {:secret=>\"<hidden>\"}] | bad data").once
      @client.send(:log_failure, @url, @path, {:secret => "data"}, ["secret"], "uuid", @now, "bad data").should be true
    end
  end

  context :log_text do
    before(:each) do
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    context "when no exception" do
      it "generates text containing containing host, path, and filtered parameters" do
        @log.should_receive(:level).and_return(:debug)
        text = @client.send(:log_text, @path, {:some => "data", :secret => "data"}, ["secret"], @url)
        text.should == "[http://my.com/foo/bar {:some=>\"data\", :secret=>\"<hidden>\"}]"
      end
    end

    context "when exception" do
      it "includes params regardless of Log.level" do
        text = @client.send(:log_text, @path, {:some => "data", :secret => "data"}, ["secret"], @url, "failed")
        text.should == "[http://my.com/foo/bar {:some=>\"data\", :secret=>\"<hidden>\"}] | failed"
      end

      it "includes exception text" do
        exception = RightScale::HttpExceptions.create(400, "bad data")
        text = @client.send(:log_text, @path, {:some => "data", :secret => "data"}, ["secret"], @url, exception)
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

    it "also applies filters to any parameter named :payload or 'payload'" do
      filter = ["secret", "very_secret"]
      params = {:some => 1, :payload => {:secret => "data"}, "payload" => {:very_secret => "data"}, :secret => "data"}
      @client.send(:filter, params, filter).should == {:some => 1, :payload => {:secret => "<hidden>"},
                                                       "payload" => { :very_secret => "<hidden>"}, :secret => "<hidden>"}
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

  context :format do
    before(:each) do
      @client = RightScale::BalancedHttpClient
    end

    it "converts param to key=value format" do
      @client.format({:foo => "bar"}).should == "foo=bar"
    end

    it "escapes param value" do
      @client.format({:path => "/foo/bar"}).should == "path=%2Ffoo%2Fbar"
    end

    it "breaks arrays into multiple params" do
      params = {:paths => ["/foo/bar", "/foo/bar2"]}
      @client.format(params).should == "paths[]=%2Ffoo%2Fbar&paths[]=%2Ffoo%2Fbar2"
    end

    it "separates params with '&'" do
      params = {:foo => 111, :paths => ["/foo/bar", "/foo/bar2"], :bar => 999}
      response = @client.format(params)
      response.split("&").sort.should == ["bar=999", "foo=111", "paths[]=%2Ffoo%2Fbar", "paths[]=%2Ffoo%2Fbar2"]
    end
  end

  context :process_response do
    before(:each) do
      @result = {"out" => 123}
      @body = JSON.dump({:out => 123})
      @client = RightScale::BalancedHttpClient
    end

    it "returns location header for 201 response" do
      @client.response(201, "", {:status => "201 Created", :location => "/href"}, false).should == "/href"
    end

    it "returns body without decoding by default" do
      @client.response(200, @body, {:status => "200 OK"}, false).should == @body
    end

    it "returns JSON decoded response if decoding requested" do
      @client.response(200, @body, {:status => "200 OK"}, true).should == @result
    end

    it "returns nil if JSON decoded response is empty" do
      @client.response(200, "null", {:status => "200 OK"}, true).should be nil
    end

    it "returns nil if response is empty" do
      @client.response(204, nil, {:status => "204 No Content"}, false).should be nil
    end

    it "returns nil if response is nil" do
      @client.response(200, nil, {:status => "200 OK"}, false).should be nil
    end

    it "returns nil if body is empty" do
      @client.response(200, "", {:status => "200 OK"}, false).should be nil
    end

    it "raises exception if response code indicates failure" do
      lambda { @client.response(400, nil, {:status => "400 Bad Request"}, false) }.should raise_error(RightScale::HttpExceptions::BadRequest)
    end
  end

  context :exception_text do
    before(:each) do
      @client = RightScale::BalancedHttpClient
    end

    context "when string exception" do
      it "adds exception text" do
        @client.exception_text("failed").should == "failed"
      end
    end

    context "when REST exception" do
      it "adds exception code/type and any http_body" do
        exception = RightScale::HttpExceptions.create(400, "bad data")
        @client.exception_text(exception).should == "400 Bad Request: bad data"
      end

      it "adds exception code/type but omits http_body if it is html" do
        exception = RightScale::HttpExceptions.create(400, "<html> bad </html>")
        @client.exception_text(exception).should == "400 Bad Request"
      end

      it "adds exception code/type and omits http_body if it is blank" do
        exception = RightScale::HttpExceptions.create(400, "")
        @client.exception_text(exception).should == "400 Bad Request"
      end
    end

    context "when NoResult exception" do
      it "adds exception class and message" do
        exception = RightSupport::Net::NoResult.new("no result")
        @client.exception_text(exception).should == "RightSupport::Net::NoResult: no result"
      end
    end

    context "when non-REST, non-NoResult exception" do
      it "adds exception class and message" do
        exception = ArgumentError.new("bad arg")
        @client.exception_text(exception).should == "ArgumentError: bad arg"
      end
    end

    context "when non-REST, non-NoResult exception with backtrace" do
      it "adds exception class, message, and backtrace" do
        exception = ArgumentError.new("bad arg")
        flexmock(exception).should_receive(:backtrace).and_return(["line 1", "line 2"])
        @client.exception_text(exception).should == "ArgumentError: bad arg in\nline 1\nline 2"
      end
    end
  end
end
