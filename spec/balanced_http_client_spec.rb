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
require File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib', 'right_agent', 'clients', 'balanced_http_client'))

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
          :api_version => "1.0",
          :auth_proc => lambda { {"Authorization" => "Bearer <session>"} }
        }
        request_options = {
          :open_timeout => 1,
          :request_timeout => 2
        }
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

      it "uses auth_proc for setting authorization in header" do
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

    it "sends request using HTTPClient via balancer" do
      @http_client.should_receive(:post).with("#{@url}#{@path}", Hash).and_return(nil).once
      @balancer.should_receive(:request).and_yield(@url).once
      @client.send(:request, :post, @path).should be_nil
    end

    it "returns JSON decoded response" do
      @response.should_receive(:body).and_return(@json_result).times(4)
      @balancer.should_receive(:request).and_return(@response).once
      @client.send(:request, :get, @path).should == @json_decoded_result
    end

    it "returns nil if response is empty" do
      @response.should_receive(:body).and_return("").times(3)
      @balancer.should_receive(:request).and_return(@response).once
      @client.send(:request, :get, @path).should be_nil
    end

    it "returns nil if response is nil" do
      @balancer.should_receive(:request).and_return(nil).once
      @client.send(:request, :get, @path).should be_nil
    end

    it "returns nil if response status indicates no content" do
      @response.should_receive(:code).and_return(204).twice
      @balancer.should_receive(:request).and_return(@response).once
      @client.send(:request, :get, @path).should be_nil
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

      it "logs response length using header :content_length if available" do
        @response.should_receive(:headers).and_return({:status => "200 OK", :content_length => 99})
        @http_client.should_receive(:post).and_return(@response)
        @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar").once
        @log.should_receive(:info).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 99 bytes").once
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
          @log.should_receive(:level).and_return(Logger::DEBUG)
          @http_client.should_receive(:post).and_return(@response)
          @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar (#{@filtered_params})").once
          @log.should_receive(:info).with("Completed <random uuid> in 10ms | 200 [http://my.com/foo/bar] | 11 bytes {\"out\"=>123}").once
          @client.send(:request, :post, @path, @params, @options)
        end

        it "logs response failure including filtered params" do
          @http_client.should_receive(:post).and_raise(BadRequestMock.new("bad data")).once
          @log.should_receive(:info).with("Requesting POST <random uuid> /foo/bar").once
          @log.should_receive(:error).with("Failed <random uuid> in 10ms | 400 [http://my.com/foo/bar (#{@filtered_params})] | 400 Bad Request: bad data").once
          lambda { @client.send(:request, :post, @path, @params, @options) }.should raise_error(RuntimeError)
        end
      end
    end
  end

  context :report_failure do
    before(:each) do
      @started_at = Time.now
      flexmock(Time).should_receive(:now).and_return(@started_at + 0.01)
      @client = RightScale::BalancedHttpClient.new(@urls)
    end

    it "logs exception" do
      exception = BadRequestMock.new("bad data")
      @log.should_receive(:error).with("Failed <uuid> in 10ms | 400 [http://my.com/foo/bar (\"params\")] | 400 Bad Request: bad data").once
      @client.send(:report_failure, @url, @path, "params", [], "uuid", @started_at, exception)
    end

    it "logs error string" do
      @log.should_receive(:error).with("Failed <uuid> in 10ms | nil [http://my.com/foo/bar (\"params\")] | bad data").once
      @client.send(:report_failure, @url, @path, "params", [], "uuid", @started_at, "bad data")
    end

    it "filters params" do
      @log.should_receive(:error).with("Failed <uuid> in 10ms | nil [http://my.com/foo/bar ({:secret=>\"<hidden>\"})] | bad data").once
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
          @log.should_receive(:level).and_return(Logger::DEBUG)
          text = @client.send(:log_text, @path, {:some => "data", :secret => "data"}, ["secret"], @url)
          text.should == "[http://my.com/foo/bar ({:some=>\"data\", :secret=>\"<hidden>\"})]"
        end
      end
    end

    context "when exception" do
      it "includes params regardless of mode" do
        text = @client.send(:log_text, @path, {:some => "data", :secret => "data"}, ["secret"], @url, "failed")
        text.should == "[http://my.com/foo/bar ({:some=>\"data\", :secret=>\"<hidden>\"})] | failed"
      end

      it "includes exception text" do
        exception = BadRequestMock.new("bad data")
        text = @client.send(:log_text, @path, {:some => "data", :secret => "data"}, ["secret"], @url, exception)
        text.should == "[http://my.com/foo/bar ({:some=>\"data\", :secret=>\"<hidden>\"})] | 400 Bad Request: bad data"
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
      it "adds exception code/type and any message" do
        exception = BadRequestMock.new("bad data")
        RightScale::BalancedHttpClient.exception_text(exception).should == "400 Bad Request: bad data"
      end

      it "adds exception code/type but omits message if it is html" do
        exception = BadRequestMock.new("<html> bad </html>")
        RightScale::BalancedHttpClient.exception_text(exception).should == "400 Bad Request"
      end

      it "adds exception code/type and omits message if it is blank" do
        exception = BadRequestMock.new
        exception.message = nil
        RightScale::BalancedHttpClient.exception_text(exception).should == "400 Bad Request"
      end
    end

    context "when non-REST exception" do
      it "adds exception class and message" do
        exception = ArgumentError.new("bad arg")
        RightScale::BalancedHttpClient.exception_text(exception).should == "ArgumentError: bad arg"
      end
    end

    context "when non-HTTP exception with backtrace" do
      it "adds exception class, message, and backtrace" do
        exception = ArgumentError.new("bad arg")
        flexmock(exception).should_receive(:backtrace).and_return(["line 1", "line 2"])
        RightScale::BalancedHttpClient.exception_text(exception).should == "ArgumentError: bad arg in\nline 1\nline 2"
      end
    end
  end
end
