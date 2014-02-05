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
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'lib', 'right_agent', 'clients', 'auth_client'))

class AuthClientTest < RightScale::AuthClient
  def initialize(options = {})
    @identity = options[:identity]
    @api_url = options[:api_url]
    @router_url = options[:router_url]
    @account_id = options[:account_id]
    @mode = options[:mode]
    @access_token = options[:access_token]
    @state = :pending
    @status_callbacks = []
    reset_stats
  end
end

describe RightScale::AuthClient do

  include FlexMock::ArgumentTypes

  before(:each) do
    @log = flexmock(RightScale::Log)
    @log.should_receive(:error).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @log.should_receive(:warning).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @identity = "rs-agent-1-1"
    @api_url = "http://api.com"
    @router_url = "http://router.com"
    @options = {
      :identity => @identity,
      :api_url => @api_url,
      :router_url => @router_url,
      :account_id => 123,
      :mode => :http,
      :access_token => "<test access token>" }
    @client = AuthClientTest.new(@options)
  end

  context :initialize do
    it "raises if abstract class" do
      lambda { RightScale::AuthClient.new }.should raise_error(NotImplementedError, "RightScale::AuthClient is an abstract class")
    end

    it "does not raise for derived class" do
      AuthClientTest.new
    end
  end

  context :identity do
    it "returns identity" do
      @client.identity.should == @identity
    end
  end

  context :headers do
    it "raises if not authorized" do
      lambda { @client.headers }.should raise_error(RightScale::Exceptions::Unauthorized)
    end

    it "returns headers" do
      @client.send(:state=, :authorized)
      @client.headers.should == {"Authorization" => "Bearer <test access token>"}
    end
  end

  context :auth_header do
    it "raises if not authorized" do
      lambda { @client.auth_header }.should raise_error(RightScale::Exceptions::Unauthorized)
    end

    it "returns authorization header" do
      @client.send(:state=, :authorized)
      @client.auth_header.should == {"Authorization" => "Bearer <test access token>"}
    end
  end

  context :account_id do
    it "raises if not authorized" do
      lambda { @client.account_id }.should raise_error(RightScale::Exceptions::Unauthorized)
    end

    it "returns auth header" do
      @client.send(:state=, :authorized)
      @client.account_id.should == 123
    end
  end

  context :api_url do
    it "raises if not authorized" do
      lambda { @client.api_url }.should raise_error(RightScale::Exceptions::Unauthorized)
    end

    it "returns auth header" do
      @client.send(:state=, :authorized)
      @client.api_url.should == @api_url
    end
  end

  context :router_url do
    it "raises if not authorized" do
      lambda { @client.router_url }.should raise_error(RightScale::Exceptions::Unauthorized)
    end

    it "returns auth header" do
      @client.send(:state=, :authorized)
      @client.router_url.should == @router_url
    end
  end

  context :mode do
    it "returns mode" do
      @client.mode.should == :http
    end
  end

  context :expired do
    it "logs that authorization expired" do
      @log.should_receive(:info).with(/Renewing authorization/).once
      @client.send(:state=, :authorized)
      @client.expired.should be_true
    end

    it "sets state to :expired" do
      @client.send(:state=, :authorized)
      @client.expired.should be_true
      @client.state.should == :expired
    end

    it "should renew authorization" do
      @client.send(:state=, :authorized)
      flexmock(@client).should_receive(:renew_authorization).once
      @client.expired.should be_true
    end
  end

  context :redirect do
    it "handles redirect" do
      @client.redirect("location").should be_true
    end
  end

  context :close do
    it "should set state to :closed" do
      @client.close.should be_true
      @client.state.should == :closed
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

  context :check_authorized do
    it "raises retryable error if state is :expired" do
      @client.send(:state=, :authorized)
      @client.send(:expired)
      lambda { @client.send(:check_authorized) }.should raise_error(RightScale::Exceptions::RetryableError, "Authorization expired")
    end

    it "raises unauthorized if state is not :authorized" do
      lambda { @client.send(:check_authorized) }.should raise_error(RightScale::Exceptions::Unauthorized, "Not authorized with RightScale")
    end

    it "returns true if authorized" do
      @client.send(:state=, :authorized)
      @client.send(:check_authorized).should be_true
    end
  end

  context :renew_authorization do
    it "renews authorization" do
      @client.send(:renew_authorization).should be_true
    end

    it "waits to renew authorization" do
      @client.send(:renew_authorization, 10).should be_true
    end
  end

  context :state= do
    it "raises exception if state transition is invalid" do
      lambda { @client.send(:state=, :expired) }.should raise_error(ArgumentError, "Invalid state transition: :pending -> :expired")
    end

    [:pending, :closed].each do |state|
      context state do
        it "stores new state" do
          @client.send(:state=, state)
          @client.state.should == state
        end
      end
    end

    [:authorized, :unauthorized, :expired, :failed].each do |state|
      context state do
        before(:each) do
          @client.send(:state=, :authorized) if state == :expired
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
            callback_type.should == :auth
            callback_state.should == state
          end

          it "log error if callback fails" do
            @log.should_receive(:error).with("Failed status callback", StandardError).once
            @client.status { |t, s| raise StandardError, "test" }
            @client.send(:state=, state).should == state
          end
        end

        it "does nothing if current state is the same" do
          flexmock(@client.instance_variable_get(:@stats)["state"]).should_receive(:update).once
          @client.send(:state=, state)
          @client.send(:state=, state).should == state
        end
      end
    end
  end
end
