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
    @http_client = flexmock("http client", :get => true, :check_health => true).by_default
    flexmock(RightScale::BalancedHttpClient).should_receive(:new).and_return(@http_client).by_default
    @websocket = WebSocketClientMock.new
    flexmock(Faye::WebSocket::Client).should_receive(:new).and_return(@websocket).by_default
    @auth_header = {"Authorization" => "Bearer <session>"}
    @url = "http://test.com"
    @auth_client = AuthClientMock.new(@url, @auth_header, :authorized)
    @routing_keys = nil
    @options = {}
    @client = RightScale::RouterClient.new(@auth_client, @options)
    @version = RightScale::AgentConfig.protocol_version
    @event = {:uuid => "uuid", :type => "Push", :path => "/foo/bar", :from => "rs-agent-1-1", :data => {}, :version => @version}
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
        flexmock(@client).should_receive(:make_request).with(:post, "/push", @params, @action, @token).
            and_return(nil).once
        @client.push(@type, @payload, @target, @token).should be_nil
      end

      it "does not require token" do
        flexmock(@client).should_receive(:make_request).with(:post, "/push", @params, @action, nil).
            and_return(nil).once
        @client.push(@type, @payload, @target).should be_nil
      end
    end

    context :request do
      it "makes post request to router" do
        flexmock(@client).should_receive(:make_request).with(:post, "/request", @params, @action, @token).
            and_return(nil).once
        @client.request(@type, @payload, @target, @token)
      end

      it "does not require token" do
        flexmock(@client).should_receive(:make_request).with(:post, "/request", @params, @action, nil).
            and_return(nil).once
        @client.request(@type, @payload, @target).should be_nil
      end
    end
  end

  context "events" do

    before(:each) do
      @later = Time.at(@now = Time.now)
      @tick = 30
      flexmock(Time).should_receive(:now).and_return { @later += @tick }
    end

    context :notify do
      before(:each) do
        @routing_keys = ["key"]
        @params = {
          :event => @event,
          :routing_keys => @routing_keys }
      end

      it "sends using websocket if available" do
        @client.send(:connect, @routing_keys) { |_| }
        @client.notify(@event, @routing_keys).should be_true
        @websocket.sent.should == JSON.dump(@params)
      end

      it "makes post request by default" do
        flexmock(@client).should_receive(:make_request).with(:post, "/notify", @params, "notify", "uuid",
                                                             {:filter_params => ["event"]}).once
        @client.notify(@event, @routing_keys).should be_true
      end
    end

    context :listen do
      it "raises if block missing" do
        lambda { @client.listen(@routing_keys) }.should raise_error(ArgumentError, "Block missing")
      end

      it "loops forever until closed" do
        @client.close
        @client.listen(@routing_keys) { |_| }.should be_true
      end

      it "loops forever until closing" do
        @client.close(:receive)
        @client.listen(@routing_keys) { |_| }.should be_true
      end

      it "sleeps if websocket already exists" do
        @client.send(:connect, @routing_keys) { |_| }
        flexmock(@client).should_receive(:sleep).with(5).and_return { @client.close }.once
        @client.listen(@routing_keys) { |_| }
        @client.instance_variable_get(:@connect_interval).should == 30
      end

      context "when should try to connect" do
        before(:each) do
          @client.instance_variable_get(:@websocket).should be_nil
        end

        it "creates websocket" do
          flexmock(Faye::WebSocket::Client).should_receive(:new).and_return(@websocket).once
          flexmock(@client).should_receive(:sleep).and_return { @client.close }
          @client.listen(@routing_keys) { |_| }
        end

        it "periodically checks whether websocket creation was really successful" do
          flexmock(Faye::WebSocket::Client).should_receive(:new).and_return(@websocket)
          flexmock(@client).should_receive(:sleep).with(1).times(3).ordered
          flexmock(@client).should_receive(:sleep).and_return { @client.instance_variable_set(:@websocket, nil); @client.close }.once.ordered
          @client.listen(@routing_keys) { |_| }
        end

        it "sleeps if websocket creation failed because router not responding" do
          flexmock(Faye::WebSocket::Client).should_receive(:new).and_return(@websocket)
          flexmock(@client).should_receive(:sleep).with(1).and_return do
            @client.instance_variable_set(:@websocket, nil)
            @client.instance_variable_set(:@websocket_close_code, RightScale::RouterClient::WEBSOCKET_PROTOCOL_ERROR_CLOSE)
            @client.instance_variable_set(:@websocket_close_reason, "Unexpected response code: 502")
          end.once
          flexmock(@client).should_receive(:sleep).with(4).and_return { @client.close }.once
          @client.listen(@routing_keys) { |_| }
          @client.instance_variable_get(:@reconnect_interval).should == 4
          @client.instance_variable_get(:@connect_interval).should == 30
        end

        it "backs off to maximum reconnect interval" do
          flexmock(Faye::WebSocket::Client).should_receive(:new).and_return(@websocket)
          flexmock(@client).should_receive(:sleep).with(1).and_return do
            @client.instance_variable_set(:@websocket, nil)
            @client.instance_variable_set(:@websocket_close_code, RightScale::RouterClient::WEBSOCKET_PROTOCOL_ERROR_CLOSE)
            @client.instance_variable_set(:@websocket_close_reason, "Unexpected response code: 502")
          end.times(5)
          [4, 8, 16, 32].each { |t| flexmock(@client).should_receive(:sleep).with(t).once }
          flexmock(@client).should_receive(:sleep).with(60).and_return { @client.close }.once
          @client.listen(@routing_keys) { |_| }
          @client.instance_variable_get(:@reconnect_interval).should == 60
        end

        it "adjusts connect interval if websocket creation was unsuccessful" do
          flexmock(Faye::WebSocket::Client).should_receive(:new).and_return(@websocket)
          flexmock(@client).should_receive(:sleep).and_return { @client.instance_variable_set(:@websocket, nil); @client.close }.once
          @client.listen(@routing_keys) { |_| }
          @client.instance_variable_get(:@connect_interval).should == 60
          @client.instance_variable_get(:@reconnect_interval).should == 2
        end

        it "loops instead of long-polling if websocket creation was unsuccessful" do
          flexmock(Faye::WebSocket::Client).should_receive(:new).and_return(@websocket)
          flexmock(@client).should_receive(:sleep).and_return { @client.instance_variable_set(:@websocket, nil); @client.close }
          flexmock(@client).should_receive(:long_poll).never
          @client.listen(@routing_keys) { |_| }
        end

        it "sleeps after successfully creating websocket" do
          flexmock(Faye::WebSocket::Client).should_receive(:new).and_return(@websocket)
          flexmock(@client).should_receive(:sleep).with(1).times(4).ordered
          flexmock(@client).should_receive(:sleep).with(1).and_return { @client.close }.once.ordered
          @client.listen(@routing_keys) { |_| }
        end

        it "adjusts connect interval if websocket creation fails" do
          @log.should_receive(:error).with("Failed creating WebSocket", StandardError).once
          flexmock(@client).should_receive(:long_poll).and_return { @client.close }.once
          flexmock(Faye::WebSocket::Client).should_receive(:new).and_raise(StandardError).once
          flexmock(@client).should_receive(:sleep).never
          @client.listen(@routing_keys) { |_| }
          @client.instance_variable_get(:@connect_interval).should == 60
        end

        it "backs off to maximum connect interval" do
          @tick = 60
          @log.should_receive(:error).with("Failed creating WebSocket", StandardError).times(12)
          flexmock(@client).should_receive(:long_poll).times(2870).ordered
          flexmock(@client).should_receive(:long_poll).and_return { @client.close }.once.ordered
          flexmock(Faye::WebSocket::Client).should_receive(:new).and_raise(StandardError).times(12)
          flexmock(@client).should_receive(:sleep)
          @client.listen(@routing_keys) { |_| }
          @client.instance_variable_get(:@connect_interval).should == 60 * 60 * 24
        end
      end

      context "when could not connect" do
        before(:each) do
          flexmock(@client).should_receive(:retry_connect?).and_return(false)
        end

        it "uses long-polling" do
          flexmock(@client).should_receive(:long_poll).and_return { @client.close; ["uuid"] }.once
          @client.listen(@routing_keys) { |_| }.should be_true
        end

        it "passes events to ack in long-polling request" do
          flexmock(@client).should_receive(:long_poll).with(@routing_keys, [], Proc).and_return { @client.close; ["uuid"] }.once
          @client.listen(@routing_keys) { |_| }.should be_true
        end

        it "sleeps if there is a long-polling failure" do
          @log.should_receive(:error).with("Failed long-polling", StandardError, :trace).once
          flexmock(@client).should_receive(:long_poll).and_raise(StandardError).once
          flexmock(@client).should_receive(:sleep).with(5).and_return { @client.close }.once
          @client.listen(@routing_keys) { |_| }.should be_true
        end

        [RightScale::Exceptions::Unauthorized,
         RightScale::Exceptions::ConnectivityFailure,
         RightScale::Exceptions::RetryableError].each do |e|
          it "does not trace #{e} exceptions" do
            @log.should_receive(:error).with("Failed long-polling", e, :no_trace).once
            flexmock(@client).should_receive(:long_poll).and_raise(e, "failed").once
            flexmock(@client).should_receive(:sleep).with(5).and_return { @client.close }.once
            @client.listen(@routing_keys) { |_| }.should be_true
          end
        end
      end
    end

    context :close do
      it "closes websocket" do
        @client.send(:connect, nil) { |_| }
        @client.close
        @websocket.closed.should be_true
        @websocket.code.should == 1001
      end
    end

    context :retry_connect? do
      it "requires websocket to be enabled" do
        @client = RightScale::RouterClient.new(@auth_client, :long_polling_only => true)
        @client.send(:retry_connect?, @now, 30).should be_false
      end

      it "requires there be no existing websocket connection" do
        @client.instance_variable_set(:@websocket, @websocket)
        @client.send(:retry_connect?, @now, 30).should be_false
      end

      context "when no existing websocket" do
        before(:each) do
          @client.instance_variable_get(:@websocket).should be_nil
        end

        it "allows retry if enough time has elapsed" do
          @tick = 1
          @client.send(:retry_connect?, @now - 29, 30).should be_false
          @client.send(:retry_connect?, @now - 30, 30).should be_true
        end

        [RightScale::RouterClient::WEBSOCKET_NORMAL_CLOSE, RightScale::RouterClient::WEBSOCKET_SHUTDOWN_CLOSE].each do |code|
          it "allows retry if previous close code is #{code}" do
            @client.instance_variable_set(:@websocket_close_code, code)
            @client.send(:retry_connect?, @now, 300).should be_true
          end
        end

        [502, 503].each do |code|
          it "allows retry if previous close has reason with code #{code} indicating router inaccessible" do
            @client.instance_variable_set(:@websocket_close_code, RightScale::RouterClient::WEBSOCKET_PROTOCOL_ERROR_CLOSE)
            @client.instance_variable_set(:@websocket_close_reason, "Unexpected response code: #{code}")
            @client.send(:retry_connect?, @now, 300).should be_true
          end
        end
      end
    end

    context :connect do
      it "raises if block missing" do
        lambda { @client.send(:connect, @routing_keys) }.should raise_error(ArgumentError, "Block missing")
      end

      context "when creating connection" do
        it "connects to router" do
          flexmock(Faye::WebSocket::Client).should_receive(:new).with(@url + "/connect", nil, Hash).and_return(@websocket).once
          @client.send(:connect, @routing_keys) { |_| }
        end

        it "uses headers containing only API version and authorization" do
          headers = @auth_header.merge("X-API-Version" => "2.0")
          flexmock(Faye::WebSocket::Client).should_receive(:new).with(String, nil, hsh(:headers => headers)).and_return(@websocket).once
          @client.send(:connect, @routing_keys) { |_| }
        end

        it "enables ping" do
          flexmock(Faye::WebSocket::Client).should_receive(:new).with(String, nil, hsh(:ping => 60)).and_return(@websocket).once
          @client.send(:connect, @routing_keys) { |_| }
        end

        it "adds routing keys as query parameters" do
          url = @url + "/connect" + "?routing_keys[]=a%3Ab%3Dc"
          flexmock(Faye::WebSocket::Client).should_receive(:new).with(url, nil, Hash).and_return(@websocket).once
          @client.send(:connect, ["a:b=c"]) { |_| }
        end

        it "returns websocket" do
          flexmock(Faye::WebSocket::Client).should_receive(:new).and_return(@websocket).once
          @client.send(:connect, @routing_keys) { |_| }.should == @websocket
          @client.instance_variable_get(:@websocket).should == @websocket
        end
      end

      context "when message received" do
        before(:each) do
          @json_event = JSON.dump(@event)
          @json_ack = JSON.dump({:ack => "uuid"})
        end

        it "presents JSON-decoded event to the specified handler" do
          event = nil
          @client.send(:connect, @routing_keys) { |e| event = e }
          @websocket.onmessage(@json_event)
          event.should == @event
        end

        it "logs event" do
          @log.should_receive(:info).with("Creating WebSocket connection to http://test.com/connect").once.ordered
          @log.should_receive(:info).with("Received EVENT <uuid> Push /foo/bar from rs-agent-1-1").once.ordered
          @log.should_receive(:info).with("Sending EVENT <uuid> Push /foo/bar to rs-agent-1-1").once.ordered
          event = nil
          @client.send(:connect, @routing_keys) { |e| event = e }
          @websocket.onmessage(@json_event)
          event.should == @event
        end

        it "acknowledges event" do
          @client.send(:connect, @routing_keys) { |_| nil }
          @websocket.onmessage(@json_event)
          @websocket.sent.should == @json_ack
        end

        it "sends event response using websocket" do
          result = {:uuid => "uuid2", :type => "Result", :from => "rs-agent-2-2", :data => {}, :version => @version}
          @client.send(:connect, @routing_keys) { |_| result }
          @websocket.onmessage(@json_event)
          @websocket.sent.should == [@json_ack, JSON.dump({:event => result, :routing_keys => ["rs-agent-1-1"]})]
        end

        it "only sends non-nil responses" do
          @client.send(:connect, @routing_keys) { |_| nil }
          @websocket.onmessage(@json_event)
          @websocket.sent.should == @json_ack
        end

        it "logs failures" do
          @log.should_receive(:error).with("Failed handling WebSocket event", StandardError, :trace).once
          request = RightScale::Request.new("/foo/bar", "payload")
          @client.send(:connect, @routing_keys) { |_| raise StandardError, "bad event" }
          @websocket.onmessage(JSON.dump(request))
        end
      end

      context "on close" do
        it "logs info" do
          @log.should_receive(:info).with("Creating WebSocket connection to http://test.com/connect").once.ordered
          @log.should_receive(:info).with("WebSocket closed (1000)").once.ordered
          @client.send(:connect, @routing_keys) { |_| }
          @websocket.onclose(1000)
          @client.instance_variable_get(:@websocket).should be_nil
        end

        it "logged info includes reason if available" do
          @log.should_receive(:info).with("Creating WebSocket connection to http://test.com/connect").once.ordered
          @log.should_receive(:info).with("WebSocket closed (1001: Going Away)").once.ordered
          @client.send(:connect, @routing_keys) { |_| }
          @websocket.onclose(1001, "Going Away")
        end

        it "logs unexpected exceptions" do
          @log.should_receive(:info).with("Creating WebSocket connection to http://test.com/connect").once.ordered
          @log.should_receive(:info).and_raise(RuntimeError).once.ordered
          @log.should_receive(:error).with("Failed closing WebSocket", RuntimeError, :trace).once
          @client.send(:connect, @routing_keys) { |_| }
          @websocket.onclose(1000)
        end
      end

      context "on error" do
        it "logs error" do
          @log.should_receive(:error).with("WebSocket error (Protocol Error)")
          @client.send(:connect, @routing_keys) { |_| }
          @websocket.onerror("Protocol Error")
        end

        it "does not log if there is no error data" do
          @log.should_receive(:error).never
          @client.send(:connect, @routing_keys) { |_| }
          @websocket.onerror(nil)
        end
      end
    end

    context :long_poll do
      before(:each) do
        @ack = []
      end

      it "raises if block missing" do
        lambda { @client.send(:long_poll, @routing_keys, @ack) }.should raise_error(ArgumentError, "Block missing")
      end

      it "makes listen request to router" do
        flexmock(@client).should_receive(:make_request).with(:get, "/listen",
            on { |a| a[:wait_time].should == 55 && !a.key?(:routing_keys) &&
            a[:timestamp] == @later.to_f }, "listen", nil, Hash).and_return([@event]).once
        @client.send(:long_poll, @routing_keys, @ack) { |_| }
      end

      it "uses listen timeout for request" do
        flexmock(@client).should_receive(:make_request).with(:get, "/listen", Hash, "listen", nil,
            {:request_timeout => 60, :log_level => :debug}).and_return([@event]).once
        @client.send(:long_poll, @routing_keys, @ack) { |_| }
      end

      it "logs event" do
        @log.should_receive(:info).with("Received EVENT <uuid> Push /foo/bar from rs-agent-1-1").once
        flexmock(@client).should_receive(:make_request).and_return([@event])
        @client.send(:long_poll, @routing_keys, @ack) { |_| }
      end

      it "presents event to handler" do
        flexmock(@client).should_receive(:make_request).and_return([@event])
        event = nil
        @client.send(:long_poll, @routing_keys, @ack) { |e| event = e }
        event.should == @event
      end

      it "handles event keys that are strings" do
        event = {"uuid" => "uuid", "type" => "Push", "path" => "/foo/bar", "from" => "rs-agent-1-1", "data" => {}, "version" => @version}
        @log.should_receive(:info).with("Received EVENT <uuid> Push /foo/bar from rs-agent-1-1").once
        flexmock(@client).should_receive(:make_request).and_return([event])
        event = nil
        @client.send(:long_poll, @routing_keys, @ack) { |e| event = e }
        event.should == @event
      end

      it "does nothing if no event is returned" do
        flexmock(@client).should_receive(:make_request).and_return(nil)
        event = nil
        @client.send(:long_poll, @routing_keys, @ack) { |e| event = e }
        event.should be_nil
      end

      it "returns event UUIDs" do
        flexmock(@client).should_receive(:make_request).and_return([@event])
        @client.send(:long_poll, @routing_keys, @ack) { |_| }.should == ["uuid"]
       end
    end
  end
end