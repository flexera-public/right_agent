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
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'lib', 'right_agent', 'clients', 'router_client'))

describe RightScale::RouterClient do

  include FlexMock::ArgumentTypes

  before(:each) do
    @log = flexmock(RightScale::Log)
    @log.should_receive(:error).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @log.should_receive(:warning).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @timer = flexmock("timer", :cancel => true, :interval= => 0).by_default
    flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@timer).by_default
    @http_client = flexmock("http client", :get => true).by_default
    flexmock(RightScale::BalancedHttpClient).should_receive(:new).and_return(@http_client).by_default
    @websocket = WebSocketClientMock.new
    flexmock(Faye::WebSocket::Client).should_receive(:new).and_return(@websocket).by_default
    @auth_header = {"Authorization" => "Bearer <session>"}
    @url = "http://test.com"
    @auth_client = AuthClientMock.new(@url, @auth_header, :authorized)
    @options = {}
    @client = RightScale::RouterClient.new(@auth_client, @options)
  end

  context :initialize do
    it "initializes options" do
      @options = {
        :open_timeout => 1,
        :request_timeout => 2,
        :listen_timeout => 3,
        :retry_timeout => 4,
        :retry_intervals => [1, 2, 3],
        :reconnect_interval => 5 }
      @client = RightScale::RouterClient.new(@auth_client, @options)
      options = @client.instance_variable_get(:@options)
      options[:server_name] = "RightNet"
      options[:api_version] = "2.0"
      options[:open_timeout] = 1
      options[:request_timeout] = 2
      options[:listen_timeout] = 3
      options[:retry_timeout] = 4
      options[:retry_intervals] = [1, 2, 3]
      options[:reconnect_interval] = 5
      options[:health_check_path] = "/router/health-check"
    end

    it "initializes options to defaults if no value specified" do
      options = @client.instance_variable_get(:@options)
      options[:listen_timeout].should == 60
    end
  end

  context "requests" do

    before(:each) do
      @type = "/foo/bar"
      @action = "bar"
      @payload = {:some => "data"}
      @target = "rs-agent-2-2"
      @token = "random token"
      @params = {
        :type => @type,
        :payload => @payload,
        :target => @target }
    end

    context :push do
      it "makes post request to router" do
        flexmock(@client).should_receive(:make_request).with(:post, "/router/requests/push", @params, @action, @token).
            and_return(nil).once
        @client.push(@type, @payload, @target, @token).should be_nil
      end

      it "does not require token" do
        flexmock(@client).should_receive(:make_request).with(:post, "/router/requests/push", @params, @action, nil).
            and_return(nil).once
        @client.push(@type, @payload, @target).should be_nil
      end
    end

    context :request do
      it "makes post request to router" do
        flexmock(@client).should_receive(:make_request).with(:post, "/router/requests/request", @params, @action, @token).
            and_return(nil).once
        @client.request(@type, @payload, @target, @token)
      end

      it "does not require token" do
        flexmock(@client).should_receive(:make_request).with(:post, "/router/requests/request", @params, @action, nil).
            and_return(nil).once
        @client.request(@type, @payload, @target).should be_nil
      end
    end
  end

  context "events" do

    before(:each) do
      @now = Time.now
      @later = Time.now
      @tick = 30
      flexmock(Time).should_receive(:now).and_return { @later += @tick }
    end

    context :notify do
      before(:each) do
        @event = "event"
        @routing_key = "key"
        @params = {
          :agent_id => @auth_client.identity,
          :event => @event,
          :routing_key => @routing_key }
      end

      it "sends using websocket if available" do
        @client.send(:create_websocket) { |_| }
        @client.notify(@event, @routing_key).should be_true
        @websocket.sent.should == JSON.dump(@params)
      end

      it "makes post request by default" do
        flexmock(@client).should_receive(:make_request).with(:post, "/router/events/notify", @params, "notify").once
        @client.notify(@event, @routing_key).should be_true
      end
    end

    context :listen do
      it "raises if block missing" do
        lambda { @client.listen }.should raise_error(ArgumentError, "Block missing")
      end

      it "loops forever until closing" do
        @client.close
        @client.listen { |_| }.should be_true
      end

      it "does not use websockets if disabled" do
        @client.instance_variable_get(:@websocket).should be_nil
        @client = RightScale::RouterClient.new(@auth_client, :long_polling_only => true)
        flexmock(@client).should_receive(:long_poll).and_return { @client.close; true }.once
        @client.listen { |_| }.should be_true
      end

      context "when websocket enabled" do
        it "sleeps if websocket already exists" do
          @client.send(:create_websocket) { |_| }
          flexmock(@client).should_receive(:sleep).with(60).and_return { @client.close; true }.once
          @client.listen { |_| }
        end

        it "sleeps if websocket does not exist but not enough time has elapsed" do
          @client.send(:create_websocket) { |_| }
          flexmock(@client).should_receive(:sleep).with(60).and_return { @client.close; true }.once
          @client.listen { |_| }
        end

        it "it creates websocket if there is none and enough time has elapsed" do
          @client.instance_variable_get(:@websocket).should be_nil
          flexmock(Faye::WebSocket::Client).should_receive(:new).and_return(@websocket).once
          flexmock(@client).should_receive(:sleep).with(60).and_return { @client.close; true }
          @client.listen { |_| }
        end

        it "it sleeps after creating websocket" do
          @client.instance_variable_get(:@websocket).should be_nil
          flexmock(Faye::WebSocket::Client).should_receive(:new).and_return(@websocket)
          flexmock(@client).should_receive(:sleep).with(60).and_return { @client.close; true }.once
          @client.listen { |_| }
        end

        it "adjusts connect interval if websocket creation fails" do
          @client.instance_variable_get(:@websocket).should be_nil
          @log.should_receive(:error).with("Failed creating WebSocket", StandardError).once
          flexmock(@client).should_receive(:long_poll).and_return { @client.close; true }.once
          flexmock(Faye::WebSocket::Client).should_receive(:new).and_raise(StandardError).once
          flexmock(@client).should_receive(:sleep).with(60).never
          @client.listen { |_| }
          @client.instance_variable_get(:@connect_interval).should == 60
        end

        it "backs off to maximum connect interval" do
          @tick = 60
          @client.instance_variable_get(:@websocket).should be_nil
          @log.should_receive(:error).with("Failed creating WebSocket", StandardError).times(12)
          flexmock(@client).should_receive(:long_poll).times(2870).ordered
          flexmock(@client).should_receive(:long_poll).and_return { @client.close; true }.once.ordered
          flexmock(Faye::WebSocket::Client).should_receive(:new).and_raise(StandardError).times(12)
          flexmock(@client).should_receive(:sleep).with(60).times(2859)
          @client.listen { |_| }
          @client.instance_variable_get(:@connect_interval).should == 60 * 60 * 24
        end
      end

      context "when no websocket exists" do
        before(:each) do
          @client = RightScale::RouterClient.new(@auth_client, :long_polling_only => true)
        end

        it "uses long-polling" do
          flexmock(@client).should_receive(:long_poll).and_return { @client.close; true }.once
          @client.listen { |_| }.should be_true
        end

        it "sleeps if there is a long-polling failure" do
          @log.should_receive(:error).with("Failed long-polling", StandardError, :trace).once
          flexmock(@client).should_receive(:long_poll).and_raise(StandardError).once
          flexmock(@client).should_receive(:sleep).with(5).and_return { @client.close; true }.once
          @client.listen { |_| }.should be_true
        end

        it "does not trace connectivity errors" do
          @log.should_receive(:error).with("Failed long-polling", RightScale::Exceptions::ConnectivityError, :no_trace).once
          flexmock(@client).should_receive(:long_poll).and_raise(RightScale::Exceptions::ConnectivityError, "disconnected").once
          flexmock(@client).should_receive(:sleep).with(5).and_return { @client.close; true }.once
          @client.listen { |_| }.should be_true
        end
      end
    end

    context :create_websocket do
      it "raises if block missing" do
        lambda { @client.send(:create_websocket) }.should raise_error(ArgumentError, "Block missing")
      end

      it "creates websocket connection to router and returns it" do
        flexmock(Faye::WebSocket::Client).should_receive(:new).and_return(@websocket).once
        @client.send(:create_websocket) { |_| }
        @client.instance_variable_get(:@websocket).should == @websocket
      end

      context "when message received" do
        it "presents JSON-decoded events to the specified handler" do
          @log.should_receive(:info).with("Received event: {\"some\"=>\"event\"}").once
          event = nil
          @client.send(:create_websocket) { |e| event = e }
          @websocket.onmessage(JSON.dump({"some" => "event"}))
          event.should == {"some" => "event"}
        end

        it "logs event type instead of event if possible" do
          @log.should_receive(:info).with("Received event: /foo/bar").once
          request = RightScale::Request.new("/foo/bar", "payload")
          event = nil
          @client.send(:create_websocket) { |e| event = e }
          @websocket.onmessage(JSON.dump(request))
          event.type.should == "/foo/bar"
          event.payload.should == "payload"
        end

        it "sends response to event using websocket" do
          request = RightScale::Request.new("/foo/bar", "payload")
          response = {:some => "response"}
          @client.send(:create_websocket) { |_| response }
          @websocket.onmessage(JSON.dump(request))
          @websocket.sent.should == JSON.dump(response)
        end

        it "only sends non-nil responses" do
          request = RightScale::Request.new("/foo/bar", "payload")
          @client.send(:create_websocket) { |_| nil }
          @websocket.onmessage(JSON.dump(request))
          @websocket.sent.should be_nil
        end

        it "logs failures" do
          @log.should_receive(:error).with("Failed handling event", StandardError, :trace).once
          request = RightScale::Request.new("/foo/bar", "payload")
          @client.send(:create_websocket) { |_| raise StandardError, "bad event" }
          @websocket.onmessage(JSON.dump(request))
        end
      end

      context "on close" do
        it "logs info" do
          @log.should_receive(:info).with("Closing WebSocket (1000)").once
          @client.send(:create_websocket) { |_| }
          @websocket.onclose(1000)
          @client.instance_variable_get(:@websocket).should be_nil
        end

        it "logged info includes reason if available" do
          @log.should_receive(:info).with("Closing WebSocket (1001: Going Away)").once
          @client.send(:create_websocket) { |_| }
          @websocket.onclose(1001, "Going Away")
        end
      end

      context "on error" do
        it "logs error" do
          @log.should_receive(:error).with("Error on WebSocket (Protocol Error)")
          @client.send(:create_websocket) { |_| }
          @websocket.onerror("Protocol Error")
        end
      end
    end

    context :long_poll do
      it "raises if block missing" do
        lambda { @client.send(:long_poll) }.should raise_error(ArgumentError, "Block missing")
      end

      it "makes listen request to router" do
        @log.should_receive(:info).with("Received event: {\"some\"=>\"event\"}").once
        flexmock(@client).should_receive(:make_request).with(:get, "/router/events/listen",
            on { |a| a[:agent_id] == @auth_client.identity && a[:wait_time].should == 55 && a[:timestamp] == @later.to_f },
            "listen", nil, Hash).and_return({"some" => "event"}).once
        @client.send(:long_poll) { |_| }
      end

      it "uses listen timeout for request" do
        flexmock(@client).should_receive(:make_request).with(:get, "/router/events/listen", Hash, "listen", nil,
            {:request_timeout => 60}).and_return({"some" => "event"}).once
        @client.send(:long_poll) { |_| }
      end

      it "logs event type instead of event if possible" do
        @log.should_receive(:info).with("Received event: /foo/bar").once
        request = RightScale::Request.new("/foo/bar", "payload")
        flexmock(@client).should_receive(:make_request).and_return(request)
        @client.send(:long_poll) { |_| }
      end

      it "presents event to handler" do
        request = RightScale::Request.new("/foo/bar", "payload")
        flexmock(@client).should_receive(:make_request).and_return(request)
        event = nil
        @client.send(:long_poll) { |e| event = e }
        event.should == request
      end

      it "does nothing if no event is returned" do
        flexmock(@client).should_receive(:make_request).and_return(nil)
        event = nil
        @client.send(:long_poll) { |e| event = e }
        event.should be_nil
      end
    end
  end

  context :close do
    it "closes websocket" do
      @client.send(:create_websocket) { |_| }
      @client.close
      @websocket.closed.should be_true
    end
  end
end