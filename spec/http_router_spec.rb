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

require 'global_session'

require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib', 'right_infrastructure_agent', 'http_router'))

class InstanceApiToken; end
class EventSystem; end
class UserNotification; CATEGORY_ERROR = "error"; end

class GlobalSessionTestDirectory
  def initialize(configuration, authorities)
  end

  def configuration
    {"cookie" => {"name" => "yum"}}
  end
end

describe RightScale::HttpRouter do

  before(:each) do
    @router = RightScale::HttpRouter
    @source = "core"
    @url = "http::/localhost::8080"
    @url2 = "http::/localhost::8000"
    @urls = [@url]
    @type = "/foo/bar"
    @payload = "junk"
    @target = "rs-agent-123-1"
    @config_dir = "/tmp"
    @global_session_timeout = 3600
    @global_session_client_timeout = (@global_session_timeout * 8) / 10
    @global_session_config = flexmock("global_session configuration")
    @global_session_config.should_receive(:[]).with("directory").and_return("GlobalSessionTestDirectory").by_default
    @global_session_config.should_receive(:[]).with("timeout").and_return(@global_session_timeout).by_default
    flexmock(GlobalSession::Configuration).should_receive(:new).and_return(@global_session_config).by_default
    @global_session_dir = GlobalSessionTestDirectory.new(@global_session_config, "authorities")
    @global_session = flexmock("global session")
    @global_session.should_receive(:[]=).by_default
    @global_session.should_receive(:directory).and_return(@global_session_dir).by_default
    @global_session.should_receive(:to_s).and_return("cookie").by_default
    flexmock(GlobalSession::Session).should_receive(:new).and_return(@global_session).by_default
    @balancer = flexmock("balancer")
    flexmock(RightSupport::Net::RequestBalancer).should_receive(:new).and_return(@balancer).by_default
    @logger = flexmock("logger")
    @logger.should_receive(:info).by_default
    @logger.should_receive(:error).by_default
    @logger.should_receive(:level).and_return(Logger::INFO).by_default
    RightScale::HttpRouter::Client.const_set(:RAILS_DEFAULT_LOGGER, @logger)
  end

  context :init do

    it "must be called prior to making requests" do
      lambda { RightScale::HttpRouter.send(:client) }.should raise_error(Exception, /init was not called/)
    end

    it "creates client" do
      RightScale::HttpRouter.init(@source, @urls, @config_dir)
      RightScale::HttpRouter.send(:client).should be_a(RightScale::HttpRouter::Client)
      RightScale::HttpRouter.send(:client).instance_variable_get(:@filter_params).should == []
    end

    it "creates client using options" do
      RightScale::HttpRouter.init(@source, @urls, @config_dir, :filter_params => ["sensitive_data"])
      RightScale::HttpRouter.send(:client).should be_a(RightScale::HttpRouter::Client)
      RightScale::HttpRouter.send(:client).instance_variable_get(:@filter_params).should == ["sensitive_data"]
    end
  end

  context "usage" do

    before(:each) do
      @client = flexmock("client")
      flexmock(@router).should_receive(:client).and_return(@client).by_default
    end

    context :push do

      it "makes request" do
        @client.should_receive(:make_request).with("/router/push", @type, @payload, @target).once
        @router.push(@type, @payload, @target).should be_true
      end

      it "defaults payload and target to nil" do
        @client.should_receive(:make_request).with("/router/push", @type, nil, nil).once
        @router.push(@type).should be_true
      end
    end

    context :persistent_push do

      it "makes request" do
        @client.should_receive(:make_request).with("/router/persistent_push", @type, @payload, @target)
        @router.persistent_push(@type, @payload, @target).should be_true
      end

      it "defaults payload and target to nil" do
        @client.should_receive(:make_request).with("/router/persistent_push", @type, nil, nil).once
        @router.persistent_push(@type).should be_true
      end
    end

    context :retryable_request do

      it "makes request" do
        @client.should_receive(:make_request).with("/router/retryable_request", @type, @payload, @target).and_return("result").once
        @router.retryable_request(@type, @payload, @target).should == "result"
      end

      it "defaults payload and target to nil" do
        @client.should_receive(:make_request).with("/router/retryable_request", @type, nil, nil).and_return("result").once
        @router.retryable_request(@type).should be_true
      end
    end

    context :create_certificate do

      it "creates certificate" do
        @router.create_certificate("uuid")[0].is_a?(RightScale::Certificate)
      end
    end
  end

end # RightScale::HttpRouter


describe RightScale::HttpRouter::Client do

  include FlexMock::ArgumentTypes

  before(:each) do
    @source = "server"
    @url = "http::/localhost::8080"
    @urls = [@url]
    @config_dir = "/tmp"
    @global_session_timeout = 3600
    @global_session_client_timeout = (@global_session_timeout * 8) / 10
    @global_session_config = flexmock("global_session configuration")
    @global_session_config.should_receive(:[]).with("directory").and_return("GlobalSessionTestDirectory").by_default
    @global_session_config.should_receive(:[]).with("timeout").and_return(@global_session_timeout).by_default
    flexmock(GlobalSession::Configuration).should_receive(:new).and_return(@global_session_config).by_default
    @global_session_dir = GlobalSessionTestDirectory.new(@global_session_config, "authorities")
    @global_session = flexmock("global session")
    @global_session.should_receive(:[]=).by_default
    @global_session.should_receive(:directory).and_return(@global_session_dir).by_default
    @global_session.should_receive(:to_s).and_return("cookie").by_default
    flexmock(GlobalSession::Session).should_receive(:new).and_return(@global_session).by_default
    @balancer = flexmock("balancer")
    flexmock(RightSupport::Net::RequestBalancer).should_receive(:new).and_return(@balancer).by_default
    @logger = flexmock("logger")
    @logger.should_receive(:info).by_default
    @logger.should_receive(:error).by_default
    @logger.should_receive(:level).and_return(Logger::INFO).by_default
    RightScale::HttpRouter::Client.const_set(:RAILS_DEFAULT_LOGGER, @logger)
  end

  context :initialize do

    it "creates request balancer with health checker" do
      flexmock(RightSupport::Net::RequestBalancer).should_receive(:new).
          with(@urls, hsh(:policy => RightSupport::Net::LB::HealthCheck)).and_return(@balancer).once
      RightScale::HttpRouter::Client.new(@source, @urls, @config_dir)
    end

    it "creates global session directory" do
      flexmock(GlobalSession::Configuration).should_receive(:new).and_return(@global_session_config).once
      client = RightScale::HttpRouter::Client.new(@source, @urls, @config_dir)
      client.instance_variable_get(:@global_session_dir).is_a?(GlobalSessionTestDirectory).should be_true
    end

    it "uses default global session directory if none provided" do
      @global_session_dir = flexmock("global_session directory")
      flexmock(GlobalSession::Directory).should_receive(:new).and_return(@global_session_dir).once
      @global_session.should_receive(:directory).and_return(@global_session_dir).by_default
      @global_session_config.should_receive(:[]).with("directory").and_return(nil).once
      @global_session_config.should_receive(:[]).with("timeout").and_return(@global_session_timeout).once
      flexmock(GlobalSession::Configuration).should_receive(:new).and_return(@global_session_config).once
      RightScale::HttpRouter::Client.new(@source, @urls, @config_dir)
    end

    it "sets timeout at 80% of actual global session timeout" do
      @global_session_config.should_receive(:[]).with("directory").and_return("GlobalSessionTestDirectory").once
      @global_session_config.should_receive(:[]).with("timeout").and_return(@global_session_timeout).once
      client = RightScale::HttpRouter::Client.new(@source, @urls, @config_dir)
      client.instance_variable_get(:@global_session_timeout).should == @global_session_client_timeout
    end

    it "accepts comma-separated list of URLs" do
      flexmock(RightSupport::Net::RequestBalancer).should_receive(:new).
          with(on { |arg| arg.should == ["url1", "url2"] }, Hash).and_return(@balancer).once
      RightScale::HttpRouter::Client.new(@source, "url1, url2", @config_dir)
    end
  end

  context :make_request do

    before(:each) do
      @client = RightScale::HttpRouter::Client.new(@source, @urls, @config_dir)
      @result = {:out => 123}
      @json_result = JSON.dump(@result)
      @json_decoded_result = {"out" => 123}
      @response = flexmock("response")
      @response.should_receive(:code).and_return(200).by_default
      @response.should_receive(:body).and_return(@json_result).by_default
      @response.should_receive(:headers).and_return({:status => "200 OK"}).by_default
      flexmock(RightSupport::Data::UUID).should_receive(:generate).and_return("uuid").by_default
    end

    it "routes request using HTTPClient" do
      uri = "/router/push"
      http_client = flexmock("http client")
      http_client.should_receive(:post).with("#{@url}#{uri}", Hash).and_return(nil).once
      flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_return(http_client).once
      @balancer.should_receive(:request).and_yield(@url).once
      @client.make_request(uri, "/foo/bar", "payload", "target").should be_nil
    end

    it "uses global session for authorization" do
      uri = "/router/push"
      http_client = flexmock("http client")
      http_client.should_receive(:post).with("#{@url}#{uri}",
          on { |arg| arg[:headers]["Authorization"].should =~ /Bearer / }).and_return(nil).once
      flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_return(http_client).once
      @balancer.should_receive(:request).and_yield(@url).once
      @client.make_request(uri, "/foo/bar", "payload", "target").should be_nil
    end

    it "returns JSON decoded response" do
      @response.should_receive(:body).and_return(@json_result).times(4)
      @balancer.should_receive(:request).and_return(@response).once
      @client.make_request("/router/retryable_request", "/foo/bar", "payload", "target").should == @json_decoded_result
    end

    context "when response is empty" do
      it "returns nil" do
        @response.should_receive(:body).and_return("").times(3)
        @balancer.should_receive(:request).and_return(@response).once
        @client.make_request("/router/retryable_request", "/foo/bar", "payload", "target").should be_nil
      end
    end

    context "when response is nil" do
      it "returns nil" do
        @balancer.should_receive(:request).and_return(nil).once
        @client.make_request("/router/push", "/foo/bar", "payload", "target").should be_nil
      end
    end

    context "when response status indicates no content" do
      it "returns nil" do
        @response.should_receive(:code).and_return(204).twice
        @balancer.should_receive(:request).and_return(@response).once
        @client.make_request("/router/push", "/foo/bar", "payload", "target").should be_nil
      end
    end

    context "when request could not be delivered" do

      before(:each) do
        @uri = "/router/push"
        @now = Time.now
        sum = 0
        @elapsed = RightScale::HttpRouter::Client::RETRY_INTERVALS.map { |i| sum += i }
        flexmock(Time).should_receive(:now).and_return(@now, @now, @now, @now,
                                                       @now + @elapsed[0], @now + @elapsed[0],
                                                       @now + @elapsed[1], @now + @elapsed[1],
                                                       @now + @elapsed[2], @now + @elapsed[2],
                                                       @now + RightScale::HttpRouter::Client::RETRY_TIMEOUT).by_default
        @internal_server_error = RestClient::InternalServerError.new(response = nil, 500)
        @bad_gateway = RestClient::BadGateway.new(response = nil, 502)
        @service_unavailable = RestClient::ServiceUnavailable.new(response = nil, 503)
        @gateway_timeout = RestClient::GatewayTimeout.new(response = nil, 504)
        @retry_with = RestClient::RetryWith.new(response = nil, 449)
        @retryable_502 = RightSupport::Net::NoResult.new("bad gateway", {@url => [@bad_gateway]})
        @retryable_503 = RightSupport::Net::NoResult.new("service unavailable", {@url => [@gateway_timeout, @service_unavailable]})
        @retryable_504 = RightSupport::Net::NoResult.new("gateway timeout", {@url => [@gateway_timeout]})
        @retryable_unknown = RightSupport::Net::NoResult.new("unknown", {})
        @not_retryable = RightSupport::Net::NoResult.new("internal server error", {@url => [@internal_server_error], @url2 => [@gateway_timeout]})
      end

      [502, 503, 504].each do |code|
        it "retries up to 3 times for #{code} status code" do
          retryable = eval "@retryable_#{code}"
          flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_raise(retryable).times(3)
          @balancer.should_receive(:request).and_yield(@url).times(3).ordered
          @balancer.should_receive(:request).and_return(nil).once.ordered
          flexmock(@client).should_receive(:sleep).times(3)
          flexmock(@client).should_receive(:report_failure).never
          @client.make_request(@uri, "/foo/bar", "payload", "target").should be_nil
        end
      end

      it "retries for 449 status code" do
        flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_raise(@retry_with).once
        @balancer.should_receive(:request).and_yield(@url).once.ordered
        @balancer.should_receive(:request).and_return(nil).once.ordered
        flexmock(@client).should_receive(:sleep).once
        flexmock(@client).should_receive(:report_failure).never
        @client.make_request(@uri, "/foo/bar", "payload", "target").should be_nil
      end

      it "retries at most once for 449 status code" do
        flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_raise(@retry_with).twice
        @balancer.should_receive(:request).and_yield(@url).twice
        flexmock(@client).should_receive(:sleep).once
        flexmock(@client).should_receive(:report_failure).with(@url, @uri, "/foo/bar", "payload", "target", String,
                                                               Time, @retry_with, false).once
       lambda do
         @client.make_request(@uri, "/foo/bar", "payload", "target")
       end.should raise_error(RightScale::Exceptions::RetryableError)
      end

      it "retries up to 3 times if there are no details about why request could not be delivered" do
        flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_raise(@retryable_unknown).once
        @balancer.should_receive(:request).and_yield(@url).once.ordered
        @balancer.should_receive(:request).and_return(nil).once.ordered
        flexmock(@client).should_receive(:sleep).once
        flexmock(@client).should_receive(:report_failure).never
        @client.make_request(@uri, "/foo/bar", "payload", "target").should be_nil
      end

      it "does not retry more than 25 seconds" do
        flexmock(Time).should_receive(:now).and_return(@now, @now, @now + RightScale::HttpRouter::Client::RETRY_TIMEOUT)
        flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_raise(@retryable_503).once
        @balancer.should_receive(:request).and_yield(@url).once
        flexmock(@client).should_receive(:report_failure).with(@url, @uri, "/foo/bar", "payload", "target", String,
                                                               Time, @service_unavailable, true).once
        lambda do
          @client.make_request(@uri, "/foo/bar", "payload", "target")
        end.should raise_error(RightScale::Exceptions::ConnectivityFailure)
      end

      it "reports failure and raises ConnectivityFailure exception if retries fail" do
        flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_raise(@retryable_504).times(4)
        @balancer.should_receive(:request).and_yield(@url).times(4)
        flexmock(@client).should_receive(:sleep).times(3)
        flexmock(@client).should_receive(:report_failure).with(@url, @uri, "/foo/bar", "payload", "target", String,
                                                               Time, @gateway_timeout, true).once
        lambda do
          @client.make_request(@uri, "/foo/bar", "payload", "target")
        end.should raise_error(RightScale::Exceptions::ConnectivityFailure)
      end

      it "reports failure and raises last detailed exception if not retryable" do
        flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_raise(@not_retryable).once
        @balancer.should_receive(:request).and_yield(@url).once
        flexmock(@client).should_receive(:report_failure).with(@url, @uri, "/foo/bar", "payload", "target", String,
                                                               Time, @internal_server_error, true).once
        lambda do
          @client.make_request(@uri, "/foo/bar", "payload", "target")
        end.should raise_error(@internal_server_error)
      end
    end

    context "when far end could not process request" do
      it "reports failure without notify and raises Application exception" do
        uri = "/router/push"
        flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_raise(RestClient::UnprocessableEntity).once
        @balancer.should_receive(:request).and_yield(@url).once
        flexmock(@client).should_receive(:report_failure).with(@url, uri, "/foo/bar", "payload", "target", String,
                                                               Time, RestClient::UnprocessableEntity, false).once
        lambda do
          @client.make_request(uri, "/foo/bar", "payload", "target")
        end.should raise_error(RightScale::Exceptions::Application)
      end
    end

    context "when there is an unexpected exception" do
      it "reports failure and re-raises exception" do
        uri = "/router/push"
        flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_raise(Exception.new("test")).once
        @balancer.should_receive(:request).and_yield(@url).once
        flexmock(@client).should_receive(:report_failure).with(@url, uri, "/foo/bar", "payload", "target", String, Time, Exception, true).once
        lambda do
          @client.make_request(uri, "/foo/bar", "payload", "target")
        end.should raise_error(Exception, "test")
      end
    end

    it "logs request and response" do
      now = Time.now
      flexmock(Time).should_receive(:now).and_return(now, now + 0.01)
      flexmock(RightScale::AgentIdentity).should_receive(:generate).and_return("token")
      type = "/foo/bar"
      uri = "/router/retryable_request"
      http_client = flexmock("http client")
      http_client.should_receive(:post).with("#{@url}#{uri}", Hash).and_return(@response).once
      flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_return(http_client).once
      @logger.should_receive(:info).with("Requesting POST <uuid> #{uri}(#{type}, ...) to \"target\"").once
      @logger.should_receive(:info).with("Completed <uuid> in 10ms | 200 [http::/localhost::8080/router/retryable_request] | 11 bytes").once
      @balancer.should_receive(:request).and_yield(@url).once
      @client.make_request(uri, type, "payload", "target").should == @json_decoded_result
    end

    it "logs response length using header :content_length if available" do
      now = Time.now
      flexmock(Time).should_receive(:now).and_return(now, now + 0.01)
      flexmock(RightScale::AgentIdentity).should_receive(:generate).and_return("token")
      @response.should_receive(:headers).and_return({:status => "200 OK", :content_length => 99})
      type = "/foo/bar"
      uri = "/router/retryable_request"
      http_client = flexmock("http client")
      http_client.should_receive(:post).with("#{@url}#{uri}", Hash).and_return(@response).once
      flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_return(http_client).once
      @logger.should_receive(:info).with("Requesting POST <uuid> #{uri}(#{type}, ...) to \"target\"").once
      @logger.should_receive(:info).with("Completed <uuid> in 10ms | 200 [http::/localhost::8080/router/retryable_request] | 99 bytes").once
      @balancer.should_receive(:request).and_yield(@url).once
      @client.make_request(uri, type, "payload", "target").should == @json_decoded_result
    end

    context "when in debug mode" do
      it "also logs unfiltered payload and result" do
        @logger.should_receive(:level).and_return(Logger::DEBUG)
        now = Time.now
        flexmock(Time).should_receive(:now).and_return(now, now + 0.01)
        flexmock(RightScale::AgentIdentity).should_receive(:generate).and_return("token")
        type = "/foo/bar"
        payload = {:in => 123}
        uri = "/router/retryable_request"
        http_client = flexmock("http client")
        http_client.should_receive(:post).with("#{@url}#{uri}", Hash).and_return(@response).once
        flexmock(RightSupport::Net::HTTPClient).should_receive(:new).and_return(http_client).once
        @logger.should_receive(:info).with("Requesting POST <uuid> #{uri}(#{type}, #{payload}) to \"target\"").once
        @logger.should_receive(:info).with("Completed <uuid> in 10ms | 200 [#{@url}#{uri}] | 11 bytes {\"out\"=>123}").once
        @balancer.should_receive(:request).and_yield(@url).once
        @client.make_request(uri, type, payload, "target").should == @json_decoded_result
      end
    end
  end

  context :report_failure do

    before(:each) do
      @uri = "/router/push"
      @client = RightScale::HttpRouter::Client.new(@source, @urls, @config_dir)
      @now = Time.now
      flexmock(Time).should_receive(:now).and_return(@now)
    end

    it "logs exception" do
      @logger.should_receive(:error).with(/Failed <token>.*ArgumentError: test/).once
      @client.send(:report_failure, @url, @uri, "/foo/bar", "payload", "target", "token", @now, ArgumentError.new("test"), false)
    end

    it "logs error string" do
      @logger.should_receive(:error).with(/Failed <token>.*bad times/).once
      @client.send(:report_failure, @url, @uri, "/foo/bar", "payload", "target", "token", @now, "bad times", false)
    end

    context "when payload contains token ID" do

      before(:each) do
        @token_id = 1234
        @audit_id = 9999
        @audit = flexmock("audit entry")
        @audits = flexmock("audit entries")
        @account = flexmock("account", :audit_entries => @audits)
        @instance = flexmock("instance", :resource_uid => "uid", :account => @account)
        @token = flexmock("api token", :instance => @instance)
        @instance_id = "rs-instance-1111-#{@token_id}"
      end

      context "when payload contains audit ID" do

        context "and targeted to a specific instance" do
          it "retrieves audit entry and uses it to report event" do
            @audits.should_receive(:find_by_id).with(@audit_id).and_return(@audit).once
            flexmock(InstanceApiToken).should_receive(:find_by_id).with(@token_id).and_return(@token).once
            flexmock(EventSystem).should_receive(:event!).with(@instance, @account, UserNotification::CATEGORY_ERROR,
                "Request failed", /Failed to send/, hsh(:audit_entry => @audit)).once
            @client.send(:report_failure, @url, @uri, "/foo/bar", {:audit_id => @audit_id}, @instance_id, "token", @now, "bad times", true)
          end
        end
      end

      context "when payload does not contain audit ID" do

        context "and targeted to a specific instance" do

          context "and notify enabled" do

             it "reports event" do
               @audits.should_receive(:find_by_id).never
               flexmock(InstanceApiToken).should_receive(:find_by_id).with(@token_id).and_return(@token).once
               flexmock(EventSystem).should_receive(:event!).with(@instance, @account, UserNotification::CATEGORY_ERROR,
                   "Request failed", /Failed to send/, {}).once
               @client.send(:report_failure, @url, @uri, "/foo/bar", {}, @instance_id, "token", @now, "bad times", true)
             end
          end

          context "and notify disabled" do

             it "does not report event" do
               flexmock(EventSystem).should_receive(:event!).never
               @client.send(:report_failure, @url, @uri, "/foo/bar", {}, @instance_id, "token", @now, "bad times", false)
             end
          end
        end

        context "and not targeted to an instance" do
          it "does not report event" do
            flexmock(EventSystem).should_receive(:event!).never
            @client.send(:report_failure, @url, @uri, "/foo/bar", {}, {:scope => {:shard_id => 9}}, "token", @now, "bad times", true)
          end
        end
      end
    end
  end

  context :log_text do

    before(:each) do
      @host = "http://site"
      @uri = "/router/push"
      @client = RightScale::HttpRouter::Client.new(@source, @urls, @config_dir)
    end

    context "when no exception" do

      context "and no host" do
        it "generates text containing request data including type, payload, and target" do
          @logger.should_receive(:level).and_return(Logger::DEBUG)
          text = @client.send(:log_text, @uri, "/foo/bar", {:value => 123}, "target")
          text.should == "/router/push(/foo/bar, {:value=>123}) to \"target\""
        end
      end

      context "and in info mode" do
        it "generates text containing request data including type and target but excluding payload" do
          text = @client.send(:log_text, @uri, "/foo/bar", {:value => 123}, {:scope => {:shard_id => 9}}, @host)
          text.should == "[http://site/router/push(/foo/bar, ...) to {:scope=>{:shard_id=>9}}]"
        end
      end

      context "and in debug mode" do
        it "generates text containing request data including type, payload, and target" do
          @logger.should_receive(:level).and_return(Logger::DEBUG)
          text = @client.send(:log_text, @uri, "/foo/bar", {:value => 123}, {:scope => {:shard_id => 9}}, @host)
          text.should == "[http://site/router/push(/foo/bar, {:value=>123}) to {:scope=>{:shard_id=>9}}]"
        end
      end
    end

    context "when exception" do

      it "includes payload regardless of mode" do
        text = @client.send(:log_text, @uri, "/foo/bar", {:value => 123}, {:scope => {:shard_id => 9}}, @host, "failed")
        text.should == "[http://site/router/push(/foo/bar, {:value=>123}) to {:scope=>{:shard_id=>9}}] | failed"
      end

      it "includes exception text" do
        e = RestClient::BadRequest.new(response = nil, 400)
        e.response = flexmock("response", :code => 400, :body => "bad")
        text = @client.send(:log_text, @uri, "/foo/bar", {:value => 123}, {:scope => {:shard_id => 9}}, @host, e)
        text.should == "[http://site/router/push(/foo/bar, {:value=>123}) to {:scope=>{:shard_id=>9}}] | 400 Bad Request: bad"
      end
    end
  end

  context :exception_text do

    before(:each) do
      @client = RightScale::HttpRouter::Client.new(@source, @urls, @config_dir)
    end

    context "when string exception" do
      it "adds exception text" do
        @client.send(:exception_text, "failed").should == "failed"
      end
    end

    context "when REST exception" do
      it "adds exception code/type and any message" do
        e = RestClient::BadRequest.new(response = nil, 400)
        e.response = flexmock("response", :code => 400, :body => "bad")
        @client.send(:exception_text, e).should == "400 Bad Request: bad"
      end

      it "adds exception code/type but omits message if it is html" do
        e = RestClient::BadRequest.new(response = nil, 400)
        e.response = flexmock("response", :code => 400, :body => "<html> bad </html>")
        @client.send(:exception_text, e).should == "400 Bad Request"
      end

      it "adds exception code/type and omits message if it is empty" do
        e = RestClient::BadRequest.new(response = nil, 400)
        e.response = flexmock("response", :code => 400, :body => "")
        @client.send(:exception_text, e).should == "400 Bad Request"
      end
    end

    context "when non-REST exception" do
      it "adds exception class and message" do
        e = ArgumentError.new("bad arg")
        @client.send(:exception_text, e).should == "ArgumentError: bad arg"
      end
    end

    context "when non-HTTP exception with backtrace" do
      it "adds exception class, message, and backtrace" do
        e = ArgumentError.new("bad arg")
        flexmock(e).should_receive(:backtrace).and_return(["line 1", "line 2"])
        @client.send(:exception_text, e).should == "ArgumentError: bad arg in\nline 1\nline 2"
      end
    end
  end

  context :filter do

    before(:each) do
      @params = {:foo => 1, :my => 2, :bar => 3}
    end

    it "applies filters" do
      @client = RightScale::HttpRouter::Client.new(@source, @urls, @config_dir, :filter_params => [:foo, :bar])
      @client.send(:filter, @params).should == {:foo => "<hidden>", :my => 2, :bar => "<hidden>"}
    end

    it "does not filter if no filters are specified" do
      @client = RightScale::HttpRouter::Client.new(@source, @urls, @config_dir)
      @client.send(:filter, @params).should == @params
    end
  end

end # RightScale::HttpRouter::Client
