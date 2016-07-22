#
# Copyright (c) 2014 RightScale Inc
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

require 'airbrake-ruby'

require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))

describe RightScale::ErrorTracker do

  include FlexMock::ArgumentTypes

  class AgentMock; end

  before(:each) do
    @agent = AgentMock.new
    @agent_name = "test_agent"
    @shard_id = 9
    @endpoint = "https://airbrake.com"
    @api_key = '1'
    @trace_level = RightScale::Agent::TRACE_LEVEL
    @tracker = RightScale::ErrorTracker.instance
    @log = flexmock(RightScale::Log)
    @brake = flexmock(Airbrake)
    @options = {
      :shard_id => @shard_id,
      :trace_level => @trace_level,
      :airbrake_endpoint => @endpoint,
      :airbrake_api_key => @api_key,
      :filter_params => [:password] }
  end

  context :init do
    it "initializes the tracker" do
      flexmock(@tracker).should_receive(:notify_init).with(@agent_name, @options).once
      @tracker.init(@agent, @agent_name, @options).should be true
      @tracker.instance_variable_get(:@agent).should == @agent
      @tracker.instance_variable_get(:@trace_level).should == @trace_level
      @tracker.exception_stats.should be_a RightSupport::Stats::Exceptions
    end
  end

  context :log do
    before(:each) do
      @tracker.init(@agent, @agent_name, :trace_level => @trace_level, :shard_id => @shard_id)
    end

    context "exception nil" do
      it "logs description" do
        @log.should_receive(:error).with("failed").once
        @tracker.log(self, "failed").should be true
      end
    end

    context "exception string" do
      it "logs error string" do
        @log.should_receive(:error).with("failed", "error").once
        @tracker.log(self, "failed", "error").should be true
      end
    end

    context "exception" do
      it "logs exception" do
        @log.should_receive(:error).with("failed", RuntimeError, :trace).once
        @tracker.log(self, "failed", RuntimeError.new("error")).should be true
      end

      it "applies trace level configured for selected exceptions" do
        @log.should_receive(:error).with("failed", RightScale::BalancedHttpClient::NotResponding, :no_trace).once
        @tracker.log(self, "failed", RightScale::BalancedHttpClient::NotResponding.new("error")).should be true
      end

      it "applies specified trace level" do
        @log.should_receive(:error).with("failed", RuntimeError, :caller).once
        @tracker.log(self, "failed", RuntimeError.new("error"), nil, :caller).should be true
      end

      it "tracks exception statistics when component is not a string" do
        request = RightScale::Request.new("/foo/bar", "payload")
        @log.should_receive(:error).with("failed", RuntimeError, :trace).once
        flexmock(@tracker).should_receive(:track).with(self, RuntimeError, request).once
        @tracker.log(self, "failed", RuntimeError.new("error"), request).should be true
      end

      it "tracks exception statistics when component is a string" do
        request = RightScale::Request.new("/foo/bar", "payload")
        @log.should_receive(:error).once
        flexmock(@tracker).should_receive(:track).with("test", RuntimeError, request).once
        @tracker.log("test", "failed", RuntimeError.new("error"), request).should be true
      end

      it "does not track exception statistics for :no_trace" do
        @log.should_receive(:error).once
        flexmock(@tracker).should_receive(:track).never
        @tracker.log(self, "failed", RuntimeError.new("error"), nil, :no_trace).should be true
      end
    end

    it "logs error if error logging fails" do
      @log.should_receive(:error).with("failed", RuntimeError, :trace).once.ordered
      @log.should_receive(:error).with("Failed to log error", RuntimeError, :trace).once.ordered
      flexmock(@tracker).should_receive(:track).and_raise(RuntimeError).once
      @tracker.log(self, "failed", RuntimeError.new("error")).should be false
    end

    it "does not raise exception even if exception logging fails" do
      @log.should_receive(:error).and_raise(RuntimeError).twice
      @tracker.log(self, "failed").should be false
    end
  end

  context :track do
    before(:each) do
      @now = Time.at(1000000)
      flexmock(Time).should_receive(:now).and_return(@now)
      @exception = RuntimeError.new("error")
      @tracker.init(@agent, @agent_name, :trace_level => @trace_level, :shard_id => @shard_id)
    end

    it "records exception in stats when component is an object" do
      @tracker.track(@agent, @exception).should be true
      @tracker.exception_stats.all.should == {"agent_mock" => {"total" => 1, "recent" => [{"count" => 1, "when" => 1000000,
                                              "type" => "RuntimeError", "message" => "error", "where" => nil}]}}
    end

    it "records exception in stats when component is a string" do
      request = RightScale::Request.new("/foo/bar", "payload")
      @tracker.track("test", @exception, request).should be true
      @tracker.exception_stats.all.should == {"test" => {"total" => 1, "recent" => [{"count" => 1, "when" => 1000000,
                                              "type" => "RuntimeError", "message" => "error", "where" => nil}]}}
    end

    it "only tracks if stats container exists" do
      @tracker.instance_variable_set(:@exception_stats, nil)
      request = RightScale::Request.new("/foo/bar", "payload")
      @tracker.track("test", @exception, request).should be true
      @tracker.exception_stats.should be nil
    end
  end

  context :notify do
    before(:each) do
      @exception = RuntimeError.new("error")
      @tracker.init(@agent, @agent_name, @options)
      @cgi_data = @tracker.instance_variable_get(:@cgi_data)
      ENV['RAILS_ENV'] = 'development'
    end

    after(:each) do
      ENV['RAILS_ENV'] = nil
    end

    it "sends notification using Airbrake" do
      @brake.should_receive(:notify).with(on { |a|
        a[:errors].first[:type] == "RuntimeError" &&
        a[:environment] == @cgi_data
      }, {}, :right_agent).once
      @tracker.notify(@exception).should be true
    end

    it "includes packet data in notification" do
      request = RightScale::Request.new("/foo/bar", {:pay => "load"}, :token => "token")
      @brake.should_receive(:notify).with(on { |a|
        a[:errors].first[:message] == "error" &&
        a[:context][:action] == 'bar' &&
        a[:params] == { :pay => 'load' } &&
        a[:session] == { :uuid => 'token' }
      }, {}, :right_agent).once

      @tracker.notify(@exception, request).should be true
    end

    it "includes event data in notification" do
      @brake.should_receive(:notify).with(on { |a|
        a[:errors].first[:message] == "error" &&
        a[:errors].first[:type] == "RuntimeError" &&
        a[:context][:action] == 'bar' &&
        a[:params] == { :pay => 'load' } &&
        a[:session] == { :uuid => 'token' }
      }, {}, :right_agent).once

      @tracker.notify(@exception, {"uuid" => "token", "path" => "/foo/bar", "data" => {:pay => "load"}}).should be true
    end

    it "adds agent class to :cgi_data in notification" do
      @brake.should_receive(:notify).with(on { |a|
        a[:environment] == @cgi_data.merge(:agent_class => 'AgentMock')
      }, {}, :right_agent).once

      @tracker.notify(@exception, packet = nil, @agent).should be true
    end

    it "adds component to notification" do
      @brake.should_receive(:notify).with(on { |a|
        a[:context][:component] == 'component'
      }, {}, :right_agent).once
      @tracker.notify(@exception, packet = nil, agent = nil, "component").should be true
    end

    it "converts non-nil, non-hash payload in packet to a hash" do
      request = RightScale::Request.new("/foo/bar", "payload", :token => "token")
      @brake.should_receive(:notify).with(on { |a|
        a[:params] == { :param => 'payload' }
      }, {}, :right_agent).once
      @tracker.notify(@exception, request).should be true
    end

    it "converts non-nil, non-hash data in event to a hash" do
      @brake.should_receive(:notify).with(on { |a|
        a[:params] == { :param => 'payload' }
      }, {}, :right_agent).once
      @tracker.notify(@exception, {"uuid" => "token", "path" => "/foo/bar", "data" => "payload"}).should be true
    end

    it "omits :parameters from notification if payload in packet is nil" do
      request = RightScale::Request.new("/foo/bar", nil, :token => "token")
      @brake.should_receive(:notify).with(on { |a|
        a[:params] == {}
      }, {}, :right_agent).once
      @tracker.notify(@exception, request).should be true
    end

    it "omits :parameters from notification if data in packet is nil" do
      @brake.should_receive(:notify).with(on { |a|
        a[:params] == {}
      }, {}, :right_agent).once
      @tracker.notify(@exception, {"uuid" => "token", "path" => "/foo/bar", "data" => nil}).should be true
    end

    it "functions even if cgi_data has not been initialized by notify_init" do
      @tracker.instance_variable_set(:@cgi_data, nil)
      @brake.should_receive(:notify).with(on { |a|
        a[:errors].first[:message] == "error" &&
        a[:errors].first[:type] == "RuntimeError" &&
        a[:environment] == {}
      }, {}, :right_agent).once
      @tracker.notify(@exception).should be true
    end

    it "does nothing if notify is disabled" do
      @tracker.init(@agent, @agent_name, :trace_level => @trace_level, :shard_id => @shard_id)
      @brake.should_receive(:notify).never
      @tracker.notify(@exception).should be true
    end
  end

  context :notify_callback do
    it "returns proc that calls notify" do
      @tracker.init(@agent, @agent_name, @options)
      flexmock(@tracker).should_receive(:notify).with("exception", "packet", "agent", "component").once
      @tracker.notify_callback.call("exception", "packet", "agent", "component")
    end
  end

  context :stats do
    before(:each) do
      @now = Time.at(1000000)
      flexmock(Time).should_receive(:now).and_return(@now)
      @exception = RuntimeError.new("error")
      @tracker.init(@agent, @agent_name, :trace_level => @trace_level, :shard_id => @shard_id)
    end

    it "returns exception stats" do
      @tracker.track(@agent, @exception).should be true
      @tracker.stats.should == {"exceptions" => {"agent_mock" => {"total" => 1, "recent" => [{"count" => 1,
                                "when" => 1000000, "type" => "RuntimeError", "message" => "error", "where" => nil}]}}}
    end

    it "returns no exception stats if stats container not initialized" do
      @tracker.instance_variable_set(:@exception_stats, nil)
      @tracker.track(@agent, @exception).should be true
      @tracker.stats.should == {"exceptions" => nil}
    end

    it "resets stats after collecting current stats" do
      @tracker.track(@agent, @exception).should be true
      @tracker.stats(true).should == {"exceptions" => {"agent_mock" => {"total" => 1, "recent" => [{"count" => 1,
                                      "when" => 1000000, "type" => "RuntimeError", "message" => "error", "where" => nil}]}}}
      @tracker.stats.should == {"exceptions" => nil}
    end
  end

  context :notify_init do
    class ConfigMock
      attr_accessor :host, :api_key, :project_id, :project_key, :root_directory, :environment
    end

    it "does not initialize if Airbrake endpoint or API key is undefined" do
      @brake.should_receive(:configure).never
      @tracker.send(:notify_init, @agent_name, @options.merge(:airbrake_endpoint => nil))
      @tracker.instance_variable_get(:@notify_enabled).should be false
      @tracker.send(:notify_init, @agent_name, @options.merge(:airbrake_api_key => nil))
      @tracker.instance_variable_get(:@notify_enabled).should be false
    end

    it "initializes cgi data and configures Airbrake" do
      # dirty, but we need to make sure this is unset in order to progress
      Airbrake.instance_variable_set(:@notifiers, {})

      config = ConfigMock.new
      @brake.should_receive(:configure).and_yield(config).once
      @tracker.send(:notify_init, @agent_name, @options).should be true
      cgi_data = @tracker.instance_variable_get(:@cgi_data)
      cgi_data[:agent_name].should == @agent_name
      cgi_data[:pid].should be_a Integer
      cgi_data[:process].should be_a String
      cgi_data[:shard_id].should == @shard_id
      config.host.should == "https://airbrake.com"
      config.project_id.should == @api_key
      config.project_key.should == @api_key
      config.root_directory.should be_a String
      @tracker.instance_variable_get(:@notify_enabled).should be true
      @tracker.instance_variable_get(:@filter_params).should == ["password"]
    end

    it "raises exception if airbrake-ruby is not available" do
      flexmock(@tracker).should_receive(:require_succeeds?).with("airbrake-ruby").and_return(false)
      lambda do
        @tracker.send(:notify_init, @agent_name, @options)
      end.should raise_error(RuntimeError, /airbrake-ruby gem missing/)
    end
  end

  context :filter do

    before(:each) do
      @params = {:user => "me", :password => "secret"}
    end

    it "applies filters" do
      @tracker.init(@agent, @agent_name, @options)
      @tracker.send(:filter, @params).should == {:user => "me", :password => "<hidden>"}
    end

    it "converts parameter names to string form before comparison" do
      @tracker.init(@agent, @agent_name, @options)
      @tracker.send(:filter, :user => "me", "password" => "secret").should == {:user => "me", "password" => "<hidden>"}
    end

    it "does not filter if no filters are specified" do
      @tracker.init(@agent, @agent_name, @options.merge(:filter_params => nil))
      @tracker.send(:filter, @params).should == @params
    end
  end
end
