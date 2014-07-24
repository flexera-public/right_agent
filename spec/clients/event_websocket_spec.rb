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

describe RightScale::EventWebSocket do

  include FlexMock::ArgumentTypes

  before(:each) do
    @log = flexmock(RightScale::Log)
    @log.should_receive(:error).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @log.should_receive(:warning).by_default.and_return { |m| raise RightScale::Log.format(*m) }
  end

  before(:each) do
    @url = "http://my.com"
    @env = flexmock("env")
    @peer = "agent"
    @protocols = nil
    @version = RightScale::AgentConfig.protocol_version
    @old_version = version_cannot_handle_generic_events
    @options = {:peer => @peer, :protocol_version => @version}
    @faye_websocket = WebSocketClientMock.new
    flexmock(Faye::WebSocket::Client).should_receive(:new).and_return(@faye_websocket).by_default
    @websocket = RightScale::EventWebSocket.new(@url, @protocols, @options)
    @old_websocket = RightScale::EventWebSocket.new(@url, @protocols, @options.merge(:protocol_version => @old_version))
    @event = {:uuid => "uuid", :type => "Push", :path => "/foo/bar", :from => "rs-agent-1-1", :data => {}, :version => @version}
  end

  context :initialize do
    it "determines whether client can handle generic events" do
      @websocket.generic.should be true
      @old_websocket.generic.should be false
    end

    it "creates underlying websocket for client" do
      flexmock(Faye::WebSocket::Client).should_receive(:new).with(@url, @protocols, {}).and_return(@faye_websocket).once
      @websocket = RightScale::EventWebSocket.new(@url, @protocols, @options)
      @websocket.instance_variable_get(:@websocket).should == @faye_websocket
    end

    it "creates underlying websocket for server" do
      flexmock(Faye::WebSocket).should_receive(:new).with(@env, @protocols, {}).and_return(@faye_websocket).once
      @websocket = RightScale::EventWebSocket.new(@env, @protocols, @options.merge(:is_server => true))
      @websocket.instance_variable_get(:@websocket).should == @faye_websocket
    end
  end

  context :send do
    it "assigns next :msg_id to generic event and sends it JSON-encoded" do
      @websocket.send({:event => @event})
      @faye_websocket.sent.should == JSON.dump({:event => @event, :msg_id => 1})
      @websocket.send({:event => @event})
      @faye_websocket.sent.should == [JSON.dump({:event => @event, :msg_id => 1}),
                                      JSON.dump({:event => @event, :msg_id => 2})]
    end

    it "stores errback proc" do
      proc = lambda {}
      @websocket.send({:event => @event}, &proc)
      @websocket.instance_variable_get(:@errbacks).should == {1 => proc}
    end

    it "drops outer hash for non-generic event to be compatible" do
      @old_websocket.send({:event => @event})
      @faye_websocket.sent.should == JSON.dump(@event)
      @old_websocket.send(@event)
      @faye_websocket.sent.should == [JSON.dump(@event), JSON.dump(@event)]
    end
  end

  context :send_error do
    it "sends error message if generic including associated message ID" do
      @websocket.send_error(404, "Not found", {:msg_id => 3})
      @faye_websocket.sent.should == JSON.dump({:error => {:status => 404, :content => "Not found", :msg_id => 3}, :msg_id => 1})
    end

    it "does not require message ID to exist in supplied data" do
      @websocket.send_error(404, "Not found", "data")
      @faye_websocket.sent.should == JSON.dump({:error => {:status => 404, :content => "Not found", :msg_id => nil}, :msg_id => 1})
    end

    it "does nothing if non-generic" do
      @old_websocket.send_error(404, "Not found")
      @faye_websocket.sent.should be nil
    end
  end

  context :receive do
    it "requires message to be JSON encoded and drops message and returns nil if not" do
      @log.should_receive(:error).with("Cannot JSON decode WebSocket message").once
      @websocket.receive("message").should be nil
    end

    it "requires a generic message to contain a message ID and drops message and sends back error if not" do
      @log.should_receive(:error).with("Ignoring WebSocket message from agent because missing :msg_id").once
      @websocket.receive(JSON.dump({:ack => "uuid"})).should be nil
      @faye_websocket.sent.should == JSON.dump({:error => {:status => 400, :content => "Invalid WebSocket message, " +
          "missing :msg_id", :msg_id => nil}, :msg_id => 1})
    end

    it "requires message ID to be in sequence and closes connection if not" do
      @log.should_receive(:error).with("WebSocket message with ID 3 is out of sequence, expected 2, closing connection").once
      @websocket.receive(JSON.dump(:ack => "uuid", :msg_id => 1))
      @websocket.receive(JSON.dump(:ack => "uuid", :msg_id => 3)).should be nil
      @faye_websocket.closed.should be true
      @faye_websocket.code.should == 1011
      @faye_websocket.reason.should == "Message sequence gap"
    end

    it "requires message to be a hash and sends back error if not" do
      data = "ill-formed message"
      error = {:status => 400, :content => "Invalid message format (must be JSON-encoded hash): #{data.inspect}", :msg_id => nil}
      @log.should_receive(:error).with("Unrecognized message on WebSocket from agent: #{data.inspect}").once
      @websocket.receive(JSON.dump(data)).should be nil
      @faye_websocket.sent.should == JSON.dump({:error => error, :msg_id => 1})
    end

    it "ignores messages with an ID that was already received" do
      @log.should_receive(:info).with("Dropping WebSocket message with ID 1 because repeated, current is 2").once
      @websocket.receive(JSON.dump(:ack => "uuid", :msg_id => 1))
      @websocket.receive(JSON.dump(:ack => "uuid", :msg_id => 2))
      @websocket.receive(JSON.dump(:ack => "uuid", :msg_id => 1))
    end

    it "symbolizes the keys of the hash in the decoded message" do
      @websocket.receive(JSON.dump({"ack" => "uuid", "msg_id" => 1})).should == {:ack => "uuid", :msg_id => 1}
    end

    context "when generic message received" do
      it "handles event message" do
        event = {:event => {:uuid => "uuid"}, :routing_keys => ["1111"], :msg_id => 1}
        @websocket.receive(JSON.dump(event)).should == event
        data = nil
        @websocket.oneventmessage = lambda { |d| data = d }
        event.merge!(:msg_id => 2)
        @websocket.receive(JSON.dump(event)).should == event
        data.should == event
      end

      it "symbolizes event hash" do
        event = {"event" => {"uuid" => "uuid"}, "msg_id" => 1}
        symbolized_event = {:event => {:uuid => "uuid"}, :msg_id => 1}
        data = nil
        @websocket.oneventmessage = lambda { |d| data = d }
        @websocket.receive(JSON.dump(event)).should == symbolized_event
        data.should == symbolized_event
      end

      it "handles ack message" do
        ack = {:ack => "uuid", :msg_id => 1}
        @websocket.receive(JSON.dump(ack)).should == ack
        data = nil
        @websocket.onackmessage = lambda { |d| data = d }
        ack.merge!(:msg_id => 2)
        @websocket.receive(JSON.dump(ack)).should == ack
        data.should == ack
      end

      it "handles replay message" do
        replay = {:replay => ["1111-2"], :msg_id => 1}
        @websocket.receive(JSON.dump(replay)).should == replay
        data = nil
        @websocket.onreplaymessage = lambda { |d| data = d }
        replay.merge!(:msg_id => 2)
        @websocket.receive(JSON.dump(replay)).should == replay
        data.should == replay
      end

      it "handles error message" do
        @log.should_receive(:error).with("Error received on WebSocket for message ID 2 (404: Not found)").twice
        error = {:error => {:status => 404, :content => "Not found", :msg_id => 2}, :msg_id => 1}
        @websocket.receive(JSON.dump(error)).should == error
        data = nil
        @websocket.onerrormessage = lambda { |d| data = d }
        error.merge!(:msg_id => 2)
        @websocket.receive(JSON.dump(error)).should == error
        data.should == error
      end

      it "symbolizes error hash" do
        @log.should_receive(:error).with("Error received on WebSocket for message ID 2 (404: Not found)").once
        error = {"error" => {"status" => 404, "content" => "Not found", "msg_id" => 2}, "msg_id" => 1}
        symbolized_error = {:error => {:status => 404, :content => "Not found", :msg_id => 2}, :msg_id => 1}
        data = nil
        @websocket.onerrormessage = lambda { |d| data = d }
        @websocket.receive(JSON.dump(error)).should == symbolized_error
        data.should == symbolized_error
      end

      it "logs error if message has unexpected key but message still gets handled" do
        @log.should_receive(:error).with("Unrecognized WebSocket message key :bogus from agent").once
        ack = {:ack => "uuid", :msg_id => 1, :bogus => "data"}
        data = nil
        @websocket.onackmessage = lambda { |d| data = d }
        @websocket.receive(JSON.dump(ack)).should == ack
        data.should == ack
      end
    end

    context "when non-generic message received" do
      it "handles event message by adding outer hash" do
        event = {:event => {:uuid => "uuid"}}
        @old_websocket.receive(JSON.dump(event[:event])).should == event
        data = nil
        @old_websocket.oneventmessage = lambda { |d| data = d }
        @old_websocket.receive(JSON.dump(event[:event])).should == event
        data.should == event
      end

      it "handles ack message" do
        ack = {:ack => "uuid"}
        @old_websocket.receive(JSON.dump(ack)).should == ack
        data = nil
        @old_websocket.onackmessage = lambda { |d| data = d }
        @old_websocket.receive(JSON.dump(ack)).should == ack
        data.should == ack
      end

      it "logs error if there is any other kind of message" do
        @log.should_receive(:error).with('Unrecognized WebSocket message from agent: {:bogus=>"data"}').once
        bogus = {:bogus => "data"}
        @old_websocket.receive(JSON.dump(bogus)).should be nil
      end
    end
  end

  context :receive_error do
    before(:each) do
      @error = {:error => {:status => 404, :content => "Not found", :msg_id => 2}, :msg_id => 1}
    end

    it "logs error" do
      @log.should_receive(:error).with("Error received on WebSocket for message ID 2 (404: Not found)").once
      @websocket.receive_error(@error).should be true
    end

    it "omits message ID from log message if there is none" do
      @error = {:error => {:status => 404, :content => "Not found", :msg_id => nil}, :msg_id => 1}
      @log.should_receive(:error).with("Error received on WebSocket (404: Not found)").once
      @websocket.receive_error(@error).should be true
    end

    it "makes error callback if defined" do
      @log.should_receive(:error).once
      status = content = nil
      event_proc = lambda { |_,_| }
      @websocket.send({:event => @event}, &event_proc)
      ack_proc = lambda { |s, c| status = s; content = c }
      @websocket.send({:ack => "uuid"}, &ack_proc)
      @websocket.instance_variable_get(:@errbacks).should == {1 => event_proc, 2 => ack_proc}
      @websocket.receive_error(@error).should be true
      status.should == 404
      content.should == "Not found"
      @websocket.instance_variable_get(:@errbacks).should == {1 => event_proc}
    end

    it "calls the on_error_message proc if defined" do
      @log.should_receive(:error).with("Error received on WebSocket for message ID 2 (404: Not found)").once
      data = nil
      @websocket.onerrormessage = lambda { |d| data = d }
      @websocket.receive_error(@error).should be true
      data.should == @error
    end
  end

  context "on methods" do
    [:on_event_message, :on_ack_message, :on_replay_message, :on_error_message].each do |on_var|
      on_method = (on_var.to_s.gsub("_", "") + "=").to_sym
      on_proc = lambda {}
      it "stores #{on_var.inspect} proc" do
        @websocket.__send__(on_method, on_proc).should == on_proc
        @websocket.instance_variable_get(eval(":@#{on_var}")).should == on_proc
      end
    end
  end

  context :expire_errbacks do
    before(:each) do
      @later = Time.at(1000000)
      @tick = 1
      flexmock(Time).should_receive(:now).and_return { @later += @tick }
    end

    it "deletes any errbacks that have exceeded there time-to-live" do
      event_proc = lambda { |_,_| }
      @websocket.send({:event => @event}, &event_proc)
      ack_proc = lambda { |s, c| status = s; content = c }
      @websocket.send({:ack => "uuid"}, &ack_proc)
      @websocket.instance_variable_get(:@errbacks).should == {1 => event_proc, 2 => ack_proc}
      @websocket.instance_variable_get(:@active_out_ids).should == [[1, 1000001], [2, 1000002]]
      @later += 119
      @websocket.__send__(:expire_errbacks).should be true
      @websocket.instance_variable_get(:@errbacks).should == {2 => ack_proc}
      @websocket.instance_variable_get(:@active_out_ids).should == [[2, 1000002]]
    end
  end
end