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
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'lib', 'right_agent', 'clients', 'base_retry_client'))

describe RightScale::BaseRetryClient do

  include FlexMock::ArgumentTypes

  before(:each) do
    @log = flexmock(RightScale::Log)
    @log.should_receive(:error).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @log.should_receive(:warning).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @url = "http://test.com"
    @timer = flexmock("timer", :cancel => true, :interval= => 0).by_default
    flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@timer).by_default
    @http_client = flexmock("http client", :get => true).by_default
    flexmock(RightScale::BalancedHttpClient).should_receive(:new).and_return(@http_client).by_default
    @auth_header = {"Authorization" => "Bearer <session>"}
    @auth_client = AuthClientMock.new(@url, @auth_header)
    @client = RightScale::BaseRetryClient.new
    @options = {:api_version => "2.0", :health_check_path => "/health-check"}
    @client.init(:test, @auth_client, @options)
  end

  context :init do
    it "requires auth client to produce URL for specified type of client" do
      lambda { @client.init(:bogus, @auth_client, @options) }.should \
        raise_error(ArgumentError, "Auth client does not support server type :bogus")
    end

    it "requires :api_version option" do
      lambda { @client.init(:test, @auth_client, {:health_check_path => "/health-check"}) }.should \
        raise_error(ArgumentError, ":api_version option missing")
    end

    it "requires auth client to produce URL for specified type of client" do
      lambda { @client.init(:test, @auth_client, {:api_version => "2.0"}) }.should \
        raise_error(ArgumentError, ":health_check_path option missing")
    end

    it "initializes options" do
      @options = {
        :server_name => "Test",
        :api_version => "2.0",
        :open_timeout => 1,
        :request_timeout => 2,
        :retry_timeout => 3,
        :retry_intervals => [1, 2, 3],
        :reconnect_interval => 4,
        :health_check_path => "/test/health-check" }
      @client.init(:test, @auth_client, @options).should be_true
      options = @client.instance_variable_get(:@options)
      options[:server_name].should == "Test"
      options[:api_version].should == "2.0"
      options[:open_timeout].should == 1
      options[:request_timeout].should == 2
      options[:retry_timeout].should == 3
      options[:retry_intervals].should == [1, 2, 3]
      options[:reconnect_interval].should == 4
      options[:health_check_path].should == "/test/health-check"
    end

    it "initializes options to defaults if no value specified" do
      options = @client.instance_variable_get(:@options)
      options[:server_name].should == "test"
      options[:open_timeout].should == 2
      options[:request_timeout].should == 35
      options[:retry_timeout].should == 25
      options[:retry_intervals].should == [4, 12, 36]
      options[:reconnect_interval].should == 15
    end

    it "does not default some options" do
      options = @client.instance_variable_get(:@options)
      options[:retry_enabled].should be_nil
      options[:filter_params].should be_nil
      options[:exception_callback].should be_nil
    end

    it "initializes state to :pending" do
      @client.state.should == :pending
    end

    it "initiates establishing connection" do
      flexmock(@client).should_receive(:reconnect).with(0).once
      @client.init(:test, @auth_client, @options).should be_true
    end
  end

  context :status do
    it "stores callback" do
      callback = lambda { |_, _| }
      @client.instance_variable_get(:@status_callbacks).size.should == 0
      @client.status(&callback)
      @client.instance_variable_get(:@status_callbacks).size.should == 1
      @client.instance_variable_get(:@status_callbacks)[0].should == callback
    end

    it "treats callback as optional" do
      @client.instance_variable_get(:@status_callbacks).size.should == 0
      @client.status
      @client.instance_variable_get(:@status_callbacks).size.should == 0
    end

    it "returns current state" do
      @client.status.should == :pending
    end
  end

  context :close do
    it "sets state to :closing" do
      @client.close
      @client.state.should == :closing
    end

    it "cancels reconnect timer" do
      @timer.should_receive(:cancel).once
      @client.close
    end
  end

  context :state= do
    it "raises exception if state transition is invalid" do
      @client.send(:state=, :connected)
      lambda { @client.send(:state=, :pending) }.should raise_error(ArgumentError, "Invalid state transition: :connected -> :pending")
    end

    [:pending, :closing].each do |state|
      context state do
        it "stores new state" do
          @client.send(:state=, state)
          @client.state.should == state
        end
      end
    end

    [:connected, :disconnected, :failed].each do |state|
      context state do
        before(:each) do
          flexmock(@client).should_receive(:reconnect).by_default
        end

        it "stores new state" do
          @client.send(:state=, state)
          @client.state.should == state
        end

        it "stores new state" do
          @client.send(:state=, state).should == state
        end

        context "when callbacks" do
          it "makes callbacks with new state" do
            callback_type = callback_state = nil
            @client.status { |t, s| callback_type = t; callback_state = s }
            @client.send(:state=, state)
            callback_type.should == :test
            callback_state.should == state
          end

          it "log error if callback fails" do
            @log.should_receive(:error).with("Failed status callback", StandardError).once
            @client.status { |t, s| raise StandardError, "test" }
            @client.send(:state=, state).should == state
          end
        end

        it "reconnects only if transitioning to :disconnected" do
          flexmock(@client).should_receive(:reconnect).times(state == :disconnected ? 1 : 0)
          @client.send(:state=, state)
        end

        it "does nothing if current state is :closing" do
          flexmock(@client.instance_variable_get(:@stats)["state"]).should_receive(:update).once
          @client.send(:state=, :closing)
          @client.send(:state=, state).should == :closing
        end

        it "does nothing if current state is the same" do
          flexmock(@client.instance_variable_get(:@stats)["state"]).should_receive(:update).once
          @client.send(:state=, state)
          @client.send(:state=, state).should == state
        end
      end
    end
  end

  context :create_http_client do
    it "obtains URL from auth client" do
      @log.should_receive(:info).with("Connecting to test via \"http://test.com\"")
      @client.send(:create_http_client)
    end

    it "creates HTTP client" do
      flexmock(RightScale::BalancedHttpClient).should_receive(:new).and_return(@http_client).once
      @client.send(:create_http_client).should == @http_client
    end

    it "uses specified options" do
      @options = {
        :server_name => "Test",
        :api_version => "2.0",
        :open_timeout => 1,
        :request_timeout => 2,
        :filter_params => ["secret"],
        :health_check_path => "/health-check" }
      flexmock(RightScale::BalancedHttpClient).should_receive(:new).with(@url,
          on { |a| a[:server_name] == "Test" &&
                   a[:api_version] == "2.0" &&
                   a[:open_timeout] == 1 &&
                   a[:request_timeout] == 2 &&
                   a[:filter_params] == ["secret"] &&
                   a[:health_check_path] == "/health-check" }).and_return(@http_client).once
      @client.init(:test, @auth_client, @options)
      @client.send(:create_http_client).should == @http_client
    end
  end

  context :enable_use do
    it "should return true" do
      @client.send(:enable_use).should be_true
    end
  end

  context :check_health do
    before(:each) do
      flexmock(RightScale::BalancedHttpClient).should_receive(:new).and_return(@http_client).by_default
      @client.send(:create_http_client)
    end

    it "sends health check request using existing HTTP client" do
      @http_client.should_receive(:get).with("/health-check").once
      @client.send(:check_health)
    end

    it "sets state to :connected" do
      @client.send(:check_health)
      @client.state.should == :connected
    end

    it "returns current state" do
      @client.send(:check_health).should == :connected
    end

    it "sets state to :disconnected if server not responding" do
      @http_client.should_receive(:get).and_raise(RightScale::BalancedHttpClient::NotResponding, "out of service").once
      @client.send(:check_health).should == :disconnected
      @client.state.should == :disconnected
    end

    it "sets state to :disconnected and logs if exception unexpected" do
      @log.should_receive(:error).with("Failed test health check", StandardError).once
      @http_client.should_receive(:get).with("/health-check").and_raise(StandardError).once
      @client.send(:check_health).should == :disconnected
      @client.state.should == :disconnected
    end
  end

  context :reconnect do
    before(:each) do
      @client.instance_variable_set(:@reconnecting, nil)
    end

    it "waits specified time before reconnecting" do
      flexmock(EM::PeriodicTimer).should_receive(:new).with(5, Proc).and_return(@timer).once
      @client.send(:reconnect, 5).should be_true
    end

    it "waits random interval if no wait time is specified" do
      flexmock(@client).should_receive(:rand).with(15).and_return(10).once
      flexmock(EM::PeriodicTimer).should_receive(:new).with(10, Proc).and_return(@timer).once
      @client.send(:reconnect).should be_true
    end

    it "attempts to connect even if currently connected" do
      flexmock(EM::PeriodicTimer).should_receive(:new).with(0, Proc).and_return(@timer).and_yield
      @client.send(:create_http_client)
      @client.send(:check_health).should == :connected
      @client.send(:reconnect, 0).should be_true
    end

    it "recreates HTTP client and checks health" do
      flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@timer).and_yield
      flexmock(RightScale::BalancedHttpClient).should_receive(:new).and_return(@http_client).once
      @http_client.should_receive(:get).with("/health-check").once
      @client.send(:reconnect).should be_true
    end

    context "when health check successful" do
      it "enables use of client" do
        flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@timer).and_yield
        flexmock(@client).should_receive(:enable_use).once
        @client.send(:reconnect).should be_true
      end

      it "disables timer" do
        @timer.should_receive(:cancel).once
        flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@timer).and_yield
        @client.send(:reconnect).should be_true
        @client.instance_variable_get(:@reconnecting).should be_nil
      end

      it "does not reset timer interval" do
        @timer.should_receive(:interval=).never
        flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@timer).and_yield
        @client.send(:reconnect).should be_true
      end
    end

    context "when reconnect fails" do
      it "logs error if exception is raised" do
        flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@timer).and_yield
        flexmock(@client).should_receive(:enable_use).and_raise(StandardError).once
        @log.should_receive(:error).with("Failed test reconnect", StandardError).once
        @client.send(:reconnect).should be_true
        @client.state.should == :disconnected
      end

      it "resets the timer interval to the configured value" do
        @log.should_receive(:error).with("Failed test health check", StandardError).once
        @http_client.should_receive(:get).with("/health-check").and_raise(StandardError).once
        @timer.should_receive(:interval=).with(15).once
        flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@timer).and_yield
        @client.send(:reconnect).should be_true
      end
    end

    it "does nothing if already reconnecting" do
      flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@timer).once
      @client.send(:reconnect).should be_true
      @client.instance_variable_get(:@reconnecting).should be_true
      @client.send(:reconnect).should be_true
      @client.instance_variable_get(:@reconnecting).should be_true
    end
  end

  context :make_request do
    before(:each) do
      @path = "/foo/bar"
      @params = {:some => "data"}
      @request_uuid = "random uuid"
      @now = Time.now
      flexmock(Time).should_receive(:now).and_return(@now).by_default
      flexmock(RightSupport::Data::UUID).should_receive(:generate).and_return(@request_uuid)
      flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@timer).and_yield
      @client.instance_variable_set(:@reconnecting, nil)
      @client.init(:test, @auth_client, @options)
    end

    it "raises exception if terminating" do
      @client.close
      lambda { @client.send(:make_request, :get, @path) }.should raise_error(RightScale::Exceptions::Terminating)
    end

    it "generates a request UUID if none specified" do
      @http_client.should_receive(:get).with(@path, @params, hsh(:request_uuid => @request_uuid)).once
      @client.send(:make_request, :get, @path, @params)
    end

    it "raises exception if not connected" do
      @client.send(:state=, :failed)
      lambda { @client.send(:make_request, :get, @path) }.should raise_error(RightScale::Exceptions::ConnectivityError)
    end

    it "sets HTTP options for request" do
      @http_client.should_receive(:get).with(@path, @params,
          on { |a| a[:open_timeout] == 2 &&
                   a[:request_timeout] == 35 &&
                   a[:request_uuid] == "uuid" &&
                   a[:auth_header] == @auth_header }).once
      @client.send(:make_request, :get, @path, @params, nil, "uuid")
    end

    it "overrides HTTP options with those supplied on request" do
      @http_client.should_receive(:get).with(@path, @params,
          on { |a| a[:open_timeout] == 2 &&
                   a[:request_timeout] == 20 &&
                   a[:request_uuid] == "uuid" &&
                   a[:auth_header] == @auth_header }).once
      @client.send(:make_request, :get, @path, @params, nil, "uuid", {:request_timeout => 20})
    end

    it "makes request using HTTP client" do
      @http_client.should_receive(:get).with(@path, @params, Hash).once
      @client.send(:make_request, :get, @path, @params)
    end

    context "when exception" do
      it "handles any exceptions" do
        @http_client.should_receive(:get).and_raise(StandardError, "test").once
        flexmock(@client).should_receive(:handle_exception).with(StandardError, "type", @request_uuid, @now, 1).
            and_raise(StandardError, "failed").once
        lambda { @client.send(:make_request, :get, @path, @params, "type") }.should raise_error(StandardError, "failed")
      end

      it "uses path for request type if no request type specified" do
        @http_client.should_receive(:get).and_raise(StandardError, "test").once
        flexmock(@client).should_receive(:handle_exception).with(StandardError, @path, @request_uuid, @now, 1).
            and_raise(StandardError, "failed").once
        lambda { @client.send(:make_request, :get, @path, @params) }.should raise_error(StandardError, "failed")
      end

      it "retries if exception handling does not result in raise" do
        @http_client.should_receive(:get).and_raise(StandardError, "test").twice
        flexmock(@client).should_receive(:handle_exception).with(StandardError, @path, @request_uuid, @now, 1).
            and_return("updated uuid").once.ordered
        flexmock(@client).should_receive(:handle_exception).with(StandardError, @path, "updated uuid", @now, 2).
            and_raise(StandardError, "failed").once.ordered
        lambda { @client.send(:make_request, :get, @path, @params) }.should raise_error(StandardError, "failed")
      end
    end

    it "returns result of request" do
      @http_client.should_receive(:get).with(@path, @params, Hash).and_return("result").once
      @client.send(:make_request, :get, @path, @params).should == "result"
    end
  end

  context "make_request failures" do
    before(:each) do
      @type = "type"
      @request_uuid = "random uuid"
      @now = Time.now
      flexmock(Time).should_receive(:now).and_return(@now, @now + 10, @now + 20)
      flexmock(RightSupport::Data::UUID).should_receive(:generate).and_return(@request_uuid)
      flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@timer).and_yield
      @client.instance_variable_set(:@reconnecting, nil)
      @client.init(:test, @auth_client, @options.merge(:retry_enabled => true))
    end

    context :handle_exception do
      context "when redirect" do
        [301, 302].each do |http_code|
          it "handles #{http_code} redirect" do
            e = RestExceptionMock.new(http_code, "redirect")
            flexmock(@client).should_receive(:handle_redirect).with(e, @type, @request_uuid).once
            @client.send(:handle_exception, e, @type, @request_uuid, @now, 1)
          end
        end
      end

      it "raises if unauthorized" do
        e = RestExceptionMock.new(401, "unauthorized")
        lambda { @client.send(:handle_exception, e, @type, @request_uuid, @now, 1) }.should \
            raise_error(RightScale::Exceptions::Unauthorized, "unauthorized")
      end

      it "notifies auth client and raises retryable if session expired" do
        e = RestExceptionMock.new(403, "forbidden")
        lambda { @client.send(:handle_exception, e, @type, @request_uuid, @now, 1) }.should \
            raise_error(RightScale::Exceptions::RetryableError, "Authorization expired")
        @auth_client.expired_called.should be_true
      end

      it "handles retry with and updates request_uuid to distinguish for retry" do
        e = RestExceptionMock.new(449, "retry with")
        flexmock(@client).should_receive(:handle_retry_with).with(e, @type, @request_uuid, @now, 1).
            and_return("modified uuid").once
        @client.send(:handle_exception, e, @type, @request_uuid, @now, 1).should == "modified uuid"
      end

      it "handles internal server error" do
        e = RestExceptionMock.new(500, "test internal error")
        lambda { @client.send(:handle_exception, e, @type, @request_uuid, @now, 1) }.should \
            raise_error(RightScale::Exceptions::InternalServerError, "test internal error")
      end

      it "handles not responding" do
        e = RightScale::BalancedHttpClient::NotResponding.new("not responding")
        flexmock(@client).should_receive(:handle_not_responding).with(e, @type, @request_uuid, @now, 1).once
        @client.send(:handle_exception, e, @type, @request_uuid, @now, 1)
      end

      it "causes other HTTP exceptions to be re-raised by returning nil" do
        e = RestExceptionMock.new(400, "bad request")
        @client.send(:handle_exception, e, @type, @request_uuid, @now, 1).should be_nil
      end

      it "causes other non-HTTP exceptions to be re-raised by returning nil" do
        @client.send(:handle_exception, StandardError, @type, @request_uuid, @now, 1).should be_nil
      end
    end

    context :handle_redirect do
      it "initiates redirect by notifying auth client and raising retryable error" do
        location = "http://somewhere.com"
        e = RestExceptionMock.new(301, "moved permanently", {:location => location})
        @log.should_receive(:info).with(/Received redirect/).once.ordered
        @log.should_receive(:info).with("Requesting auth client to handle redirect to #{location.inspect}").once.ordered
        lambda { @client.send(:handle_redirect, e, @type, @request_uuid) }.should \
            raise_error(RightScale::Exceptions::RetryableError, "moved permanently")
        @auth_client.redirect_location.should == location
      end

      it "raises internal error if no redirect location is provided" do
        e = RestExceptionMock.new(301, "moved permanently")
        @log.should_receive(:info).with(/Received redirect/).once
        lambda { @client.send(:handle_redirect, e, @type, @request_uuid) }.should \
            raise_error(RightScale::Exceptions::InternalServerError, "No redirect location provided")
      end
    end

    context :handle_retry_with do
      before(:each) do
        @exception = RestExceptionMock.new(449, "retry with")
      end

      it "sleeps for configured interval and does not raise if retry still viable" do
        @log.should_receive(:error).with(/Retrying type request/).once
        flexmock(@client).should_receive(:sleep).with(4).once
        @client.send(:handle_retry_with, @exception, @type, @request_uuid, @now, 1)
      end

      it "returns modified request_uuid" do
        @log.should_receive(:error)
        flexmock(@client).should_receive(:sleep)
        @client.send(:handle_retry_with, @exception, @type, @request_uuid, @now, 1).should == "#{@request_uuid}:retry"
      end

      it "does not retry more than once" do
        lambda { @client.send(:handle_retry_with, @exception, @type, @request_uuid, @now, 2) }.should \
            raise_error(RightScale::Exceptions::RetryableError)
      end

      it "raises retryable error if retry timed out" do
        @client.init(:test, @auth_client, @options.merge(:retry_enabled => true, :retry_timeout => 10))
        lambda { @client.send(:handle_retry_with, @exception, @type, @request_uuid, @now, 1) }.should \
            raise_error(RightScale::Exceptions::RetryableError)
      end

      it "raises retryable error if retry disabled" do
        @client.init(:test, @auth_client, @options.merge(:retry_enabled => false))
        lambda { @client.send(:handle_retry_with, @exception, @type, @request_uuid, @now, 1) }.should \
            raise_error(RightScale::Exceptions::RetryableError)
      end
    end

    context :handle_not_responding do
      before(:each) do
        @exception = RightScale::BalancedHttpClient::NotResponding.new("Server not responding")
      end

      it "sleeps for configured interval and does not raise if retry still viable" do
        @log.should_receive(:error).with(/Retrying type request/).once
        flexmock(@client).should_receive(:sleep).with(4).once
        @client.send(:handle_not_responding, @exception, @type, @request_uuid, @now, 1)
      end

      it "changes sleep interval for successive retries" do
        @log.should_receive(:error).with(/Retrying type request/).once
        flexmock(@client).should_receive(:sleep).with(12).once
        @client.send(:handle_not_responding, @exception, @type, @request_uuid, @now, 2)
      end

      it "does not retry more than configured number of retry intervals" do
        lambda { @client.send(:handle_not_responding, @exception, @type, @request_uuid, @now, 4) }.should \
            raise_error(RightScale::Exceptions::ConnectivityError, /Request.*failed after 4 attempts/)
      end

      it "sets state to :disconnected and raises connectivity error if retry timed out" do
        @client.init(:test, @auth_client, @options.merge(:retry_enabled => true, :retry_timeout => 10))
        # Need to shut off reconnect, otherwise since timers are always yielding,
        # setting state to :disconnected sets it to :connected
        flexmock(@client).should_receive(:reconnect).once
        lambda { @client.send(:handle_not_responding, @exception, @type, @request_uuid, @now, 3) }.should \
            raise_error(RightScale::Exceptions::ConnectivityError, /Request.*failed after 3 attempts/)
        @client.state.should == :disconnected
      end

      it "sets state to :disconnected and raises connectivity error if retry disabled" do
        @client.init(:test, @auth_client, @options.merge(:retry_enabled => false))
        # Need to shut off reconnect, otherwise since timers are always yielding,
        # setting state to :disconnected sets it to :connected
        flexmock(@client).should_receive(:reconnect).once
        lambda { @client.send(:handle_not_responding, @exception, @type, @request_uuid, @now, 1) }.should \
            raise_error(RightScale::Exceptions::ConnectivityError, /Request.*failed/)
        @client.state.should == :disconnected
      end
    end
  end
end
