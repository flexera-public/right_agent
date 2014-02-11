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
    @path = "/foo/bar"
    @balancer = flexmock("balancer")
  end

  context :initialize do
    ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY'].each do |proxy|
      it "initializes use of proxy if #{proxy} defined in environment" do
        ENV[proxy] = "https://my.proxy.com"
        flexmock(RightSupport::Net::RequestBalancer).should_receive(:new).and_return(@balancer)
        flexmock(RestClient).should_receive(:proxy=).with("https://my.proxy.com").once
        RightScale::BalancedHttpClient.new(@urls)
        ENV.delete(proxy)
      end

      it "prepends scheme to proxy address if #{proxy} defined in environment" do
        ENV[proxy] = "1.2.3.4"
        flexmock(RightSupport::Net::RequestBalancer).should_receive(:new).and_return(@balancer)
        flexmock(RestClient).should_receive(:proxy=).with("http://1.2.3.4").once
        RightScale::BalancedHttpClient.new(@urls)
        ENV.delete(proxy)
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
      @http_client = flexmock("http client")
      flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_return(@http_client).by_default
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "calls health check proc using first URL" do
      @http_client.should_receive(:get).with("http://my0.com/health-check", Hash).once
      @client.check_health
    end

    it "calls health check proc using specified URL" do
      @http_client.should_receive(:get).with("http://my1.com/health-check", Hash).once
      @client.check_health("http://my1.com")
    end
  end

  context :request do
    before(:each) do
      @result = {:out => 123}
      @json_result = JSON.dump(@result)
      @json_decoded_result = {"out" => 123}
      @response = flexmock("response")
      @response.should_receive(:code).and_return(200).by_default
      @response.should_receive(:body).and_return(@json_result).by_default
      @response.should_receive(:headers).and_return({:status => "200 OK"}).by_default
      flexmock(RightSupport::Data::UUID).should_receive(:generate).and_return("random uuid").by_default
      @balancer.should_receive(:request).and_yield(@url).by_default
      flexmock(RightSupport::Net::RequestBalancer).should_receive(:new).and_return(@balancer).by_default
      @http_client = flexmock("http client")
      flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_return(@http_client).by_default
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    context "with no options" do
      before(:each) do
        @options = {}
        @http_client.should_receive(:get).with("#{@url}#{@path}", on { |a| @options = a }).and_return(nil)
        @client.send(:request, :get, @path).should be_nil
      end

      it "sets default open and request timeouts" do
        @options[:open_timeout].should == RightScale::BalancedHttpClient::DEFAULT_OPEN_TIMEOUT
        @options[:timeout].should == RightScale::BalancedHttpClient::DEFAULT_REQUEST_TIMEOUT
      end

      it "sets random request uuid in header" do
        @options[:headers]["X-Request-Lineage-Uuid"] == "random uuid"
      end

      it "sets response to be JSON-encoded" do
        @options[:headers][:accept] == "application/json"
      end

      it "does not set API version" do
        @options[:headers]["X-API-Version"].should be_nil
      end
    end

    context "with options" do
      before(:each) do
        @options = {}
        create_options = {
          :request_uuid => "my uuid",
          :api_version => "1.0" }
        request_options = {
          :open_timeout => 1,
          :request_timeout => 2,
          :headers => {"Authorization" => "Bearer <session>"} }
        @client = RightScale::BalancedHttpClient.new(@urls, create_options)
        @http_client.should_receive(:get).with("#{@url}#{@path}", on { |a| @options = a }).and_return(nil)
        @client.send(:request, :get, @path, nil, request_options).should be_nil
      end

      it "sets open and request timeouts" do
        @options[:open_timeout].should == 1
        @options[:timeout].should == 2
      end

      it "sets request uuid in header" do
        @options[:headers]["X-Request-Lineage-Uuid"] == "my uuid"
      end

      it "sets API version in header" do
        @options[:headers]["X-API-Version"].should == "1.0"
      end

      it "uses headers for setting authorization in header" do
        @options[:headers]["Authorization"].should == "Bearer <session>"
      end
    end

    [:get, :delete].each do |verb|
      context "with #{verb.inspect}" do
        it "uses form-encoded query option for parameters" do
          params = {:id => 10}
          @http_client.should_receive(verb).with("#{@url}#{@path}", on { |a| a[:query] == params &&
              a[:payload].nil? }).and_return(nil)
          @client.send(:request, verb, @path, params).should be_nil
        end
      end
    end

    [:post, :put].each do |verb|
      context "with #{verb.inspect}" do
        it "uses JSON-encoded payload options for parameters" do
          payload = {:pay => "load"}
          json_payload = JSON.dump(payload)
          @http_client.should_receive(verb).with("#{@url}#{@path}", on { |a| a[:payload] == json_payload &&
              a[:query].nil? }).and_return(nil).once
          @client.send(:request, verb, @path, payload).should be_nil
        end
      end
    end

    context "health check proc" do
      it "removes user and password from URL when checking health" do
        @url = "http://me:pass@my.com"
        @client = RightScale::BalancedHttpClient.new(@url, :health_check_path => "/health-check")
        @http_client.should_receive(:get).with("http://my.com/health-check", Hash).once
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

    it "sends request using HTTPClient via balancer" do
      @http_client.should_receive(:post).with("#{@url}#{@path}", Hash).and_return(nil).once
      @balancer.should_receive(:request).and_yield(@url).once
      @client.send(:request, :post, @path).should be_nil
    end

    it "returns location header for 201 response" do
      @response.should_receive(:code).and_return(201).once
      @response.should_receive(:body).and_return("").once
      @response.should_receive(:headers).and_return({:status => "201 Created", :location => "/href"}).once
      @balancer.should_receive(:request).and_return(@response).once
      @client.send(:request, :get, @path).should == "/href"
    end

    it "returns JSON decoded response" do
      @response.should_receive(:body).and_return(@json_result).once
      @balancer.should_receive(:request).and_return(@response).once
      @client.send(:request, :get, @path).should == @json_decoded_result
    end

    it "returns nil if response is empty" do
      @response.should_receive(:body).and_return("").once
      @balancer.should_receive(:request).and_return(@response).once
      @client.send(:request, :get, @path).should be_nil
    end

    it "returns nil if response is nil" do
      @balancer.should_receive(:request).and_return(nil).once
      @client.send(:request, :get, @path).should be_nil
    end

    it "returns nil if response status indicates no content" do
      @response.should_receive(:code).and_return(204).once
      @balancer.should_receive(:request).and_return(@response).once
      @client.send(:request, :get, @path).should be_nil
    end

    it "handles NoResult response from balancer" do
      no_result = RightSupport::Net::NoResult.new("no result", {})
      @log.should_receive(:error).with(/Failed <random uuid>.*#{@path}/).once
      @balancer.should_receive(:request).and_yield(@url).once
      flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_raise(no_result).once
      flexmock(@client).should_receive(:handle_no_result).with(RightSupport::Net::NoResult, @url, Proc).and_yield(no_result).once
      @client.send(:request, :get, @path)
    end

    it "reports and re-raises unexpected exception" do
      @log.should_receive(:error).with(/Failed <random uuid>.*#{@path}/).once
      @balancer.should_receive(:request).and_raise(RuntimeError).once
      lambda { @client.send(:request, :get, @path) }.should raise_error(RuntimeError)
    end

    context "when logging" do
      before(:each) do
        now = Time.now
        flexmock(Time).should_receive(:now).and_return(now, now + 0.01)
      end

      it "logs request and response" do
        @http_client.should_receive(:post).and_return(@response)
        @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar").once
        @log.should_receive(:info).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes").once
        @client.send(:request, :post, @path)
      end

      it "logs using specified log level" do
        @http_client.should_receive(:post).and_return(@response)
        @log.should_receive(:debug).with("Requesting POST <random uuid> /foo/bar").once
        @log.should_receive(:debug).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes").once
        @client.send(:request, :post, @path, {}, :log_level => :debug)
      end

      it "logs response length using header :content_length if available" do
        @response.should_receive(:headers).and_return({:status => "200 OK", :content_length => 99})
        @http_client.should_receive(:post).and_return(@response)
        @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar").once
        @log.should_receive(:info).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 99 bytes").once
        @client.send(:request, :post, @path)
      end

      it "omits user and password from logged host" do
        url = "http://111:secret@my.com"
        @client = RightScale::BalancedHttpClient.new([url])
        @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar").once
        @log.should_receive(:info).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes").once
        @http_client.should_receive(:post).with("#{url}#{@path}", Hash).and_return(@response).once
        @balancer.should_receive(:request).and_yield(url).once
        @client.send(:request, :post, @path)
      end

      context "when filtering" do
        before(:each) do
          @client = RightScale::BalancedHttpClient.new(@urls, :filter_params => [:secret])
          @params = {:public => "data", "secret" => "data", "very secret" => "data"}
          @options = {:filter_params => ["very secret"]}
          @filtered_params = "{:public=>\"data\", \"secret\"=>\"<hidden>\", \"very secret\"=>\"<hidden>\"}"
        end

        it "logs request with filtered params if in debug mode" do
          @log.should_receive(:level).and_return(:debug)
          @http_client.should_receive(:post).and_return(@response)
          @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar #{@filtered_params}").once
          @log.should_receive(:info).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes | {\"out\"=>123}").once
          @client.send(:request, :post, @path, @params, @options)
        end

        it "logs response failure including filtered params" do
          @http_client.should_receive(:post).and_raise(RestExceptionMock.new(400, "bad data")).once
          @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar").once
          @log.should_receive(:error).with("Failed <random uuid> in 10ms | 400 [http://my.com/foo/bar #{@filtered_params}] | 400 Bad Request: bad data").once
          lambda { @client.send(:request, :post, @path, @params, @options) }.should raise_error(RuntimeError)
        end
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
      gateway_timeout = RestExceptionMock.new(504, "server timeout")
      bad_request = RestExceptionMock.new(400, "bad data")
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
      gateway_timeout = RestExceptionMock.new(504, "server timeout")
      @no_result = RightSupport::Net::NoResult.new("no result", {@url => gateway_timeout})
      lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should \
        raise_error(RightScale::BalancedHttpClient::NotResponding, "server timeout")
      @yielded.should == gateway_timeout
    end

    it "uses raise NotResponding if status code is 504 and http_body is nil or empty" do
      gateway_timeout = RestExceptionMock.new(504, "")
      @no_result = RightSupport::Net::NoResult.new("no result", {@url => gateway_timeout})
      lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should \
        raise_error(RightScale::BalancedHttpClient::NotResponding, "http://my.com not responding")
      @yielded.should == gateway_timeout
    end

    [502, 503].each do |code|
      it "uses server name in NotResponding exception if status code is #{code}" do
        e = RestExceptionMock.new(code)
        @no_result = RightSupport::Net::NoResult.new("no result", {@url => e})
        lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should \
          raise_error(RightScale::BalancedHttpClient::NotResponding, "http://my.com not responding")
      end
    end

    it "raises last exception in details if not retryable" do
      bad_request = RestExceptionMock.new(400, "bad data")
      @no_result = RightSupport::Net::NoResult.new("no result", {@url => bad_request})
      lambda { @client.send(:handle_no_result, @no_result, @url, &@proc) }.should raise_error(bad_request)
      @yielded.should == bad_request
    end
  end

  context :report_failure do
    before(:each) do
      @started_at = Time.now
      flexmock(Time).should_receive(:now).and_return(@started_at + 0.01)
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "logs exception" do
      exception = RestExceptionMock.new(400, "bad data")
      @log.should_receive(:error).with("Failed <uuid> in 10ms | 400 [http://my.com/foo/bar \"params\"] | 400 Bad Request: bad data").once
      @client.send(:report_failure, @url, @path, "params", [], "uuid", @started_at, exception)
    end

    it "logs error string" do
      @log.should_receive(:error).with("Failed <uuid> in 10ms | nil [http://my.com/foo/bar \"params\"] | bad data").once
      @client.send(:report_failure, @url, @path, "params", [], "uuid", @started_at, "bad data")
    end

    it "filters params" do
      @log.should_receive(:error).with("Failed <uuid> in 10ms | nil [http://my.com/foo/bar {:secret=>\"<hidden>\"}] | bad data").once
      @client.send(:report_failure, @url, @path, {:secret => "data"}, ["secret"], "uuid", @started_at, "bad data")
    end
  end

  context :log_text do
    before(:each) do
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    context "when no exception" do

      context "in info mode with no host" do
        it "generates text containing path" do
          text = @client.send(:log_text, @path, {:value => 123}, [])
          text.should == "/foo/bar"
        end
      end

      context "in info mode with host" do
        it "generates text containing host and path" do
          text = @client.send(:log_text, @path, {:value => 123}, [], @url)
          text.should == "[http://my.com/foo/bar]"
        end
      end

      context "and in debug mode" do
        it "generates text containing containing host, path, and filtered params" do
          @log.should_receive(:level).and_return(:debug)
          text = @client.send(:log_text, @path, {:some => "data", :secret => "data"}, ["secret"], @url)
          text.should == "[http://my.com/foo/bar {:some=>\"data\", :secret=>\"<hidden>\"}]"
        end
      end
    end

    context "when exception" do
      it "includes params regardless of mode" do
        text = @client.send(:log_text, @path, {:some => "data", :secret => "data"}, ["secret"], @url, "failed")
        text.should == "[http://my.com/foo/bar {:some=>\"data\", :secret=>\"<hidden>\"}] | failed"
      end

      it "includes exception text" do
        exception = RestExceptionMock.new(400, "bad data")
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

    it "converts param names to string before comparing to filter list" do
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
        exception = RestExceptionMock.new(400, "bad data")
        RightScale::BalancedHttpClient.exception_text(exception).should == "400 Bad Request: bad data"
      end

      it "adds exception code/type but omits http_body if it is html" do
        exception = RestExceptionMock.new(400, "<html> bad </html>")
        RightScale::BalancedHttpClient.exception_text(exception).should == "400 Bad Request"
      end

      it "adds exception code/type and omits http_body if it is blank" do
        exception = RestExceptionMock.new(400)
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
