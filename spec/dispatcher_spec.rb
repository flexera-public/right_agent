#
# Copyright (c) 2009-2011 RightScale Inc
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

require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))

class Foo
  include RightScale::Actor
  expose_idempotent :bar, :index, :i_kill_you
  expose_non_idempotent :bar_non
  on_exception :handle_exception

  def index(payload)
    bar(payload)
  end

  def bar(payload)
    ['hello', payload]
  end

  def bar2(payload, request)
    ['hello', payload, request]
  end

  def bar_non(payload)
    @i = (@i || 0) + payload
  end

  def i_kill_you(payload)
    raise RuntimeError.new('I kill you!')
  end

  def handle_exception(method, deliverable, error)
  end
end

class Bar
  include RightScale::Actor
  expose :i_kill_you
  on_exception do |method, deliverable, error|
    @scope = self
    @called_with = [method, deliverable, error]
  end

  def i_kill_you(payload)
    raise RuntimeError.new('I kill you!')
  end
end

# No specs, simply ensures multiple methods for assigning on_exception callback,
# on_exception raises exception when called with an invalid argument.
class Doomed
  include RightScale::Actor
  on_exception do
  end
  on_exception lambda {}
  on_exception :doh
end

# Mock the EventMachine deferrer.
class EMMock
  def self.defer(op = nil, callback = nil)
    callback.call(op.call)
  end
end

# Mock the EventMachine deferrer but do not do callback.
class EMMockNoCallback
  def self.defer(op = nil, callback = nil)
    op.call
  end
end

describe "RightScale::Dispatcher" do

  include FlexMock::ArgumentTypes

  before(:each) do
    flexmock(RightScale::Log).should_receive(:error).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    flexmock(RightScale::Log).should_receive(:info).by_default
    @now = Time.at(1000000)
    flexmock(Time).should_receive(:now).and_return(@now).by_default
    @broker = flexmock("Broker", :subscribe => true, :publish => true).by_default
    @actor = Foo.new
    @registry = RightScale::ActorRegistry.new
    @registry.register(@actor, nil)
    @agent_id = "rs-agent-1-1"
    @agent = flexmock("Agent", :identity => @agent_id, :broker => @broker, :registry => @registry, :options => {}).by_default
    @cache = RightScale::DispatchedCache.new(@agent_id)
    @dispatcher = RightScale::Dispatcher.new(@agent, @cache)
    @dispatcher.em = EMMock
    @response_queue = RightScale::Dispatcher::RESPONSE_QUEUE
    @header = flexmock("amqp header")
    @header.should_receive(:ack).once.by_default
  end

  it "should dispatch a request" do
    req = RightScale::Request.new('/foo/bar', 'you', :token => 'token')
    res = @dispatcher.dispatch(req, @header)
    res.should(be_kind_of(RightScale::Result))
    res.token.should == 'token'
    res.results.should == ['hello', 'you']
  end

  it "should dispatch a request with required arity" do
    req = RightScale::Request.new('/foo/bar2', 'you', :token => 'token')
    res = @dispatcher.dispatch(req, @header)
    res.should(be_kind_of(RightScale::Result))
    res.token.should == 'token'
    res.results.should == ['hello', 'you', req]
  end

  it "should dispatch a request to the default action" do
    req = RightScale::Request.new('/foo', 'you', :token => 'token')
    res = @dispatcher.dispatch(req, @header)
    res.should(be_kind_of(RightScale::Result))
    res.token.should == req.token
    res.results.should == ['hello', 'you']
  end

  it "should publish result of request to response queue" do
    req = RightScale::Request.new('/foo', 'you', :token => 'token')
    req.reply_to = "rs-mapper-1-1"
    @broker.should_receive(:publish).with(hsh(:name => @response_queue),
                                          on {|arg| arg.class == RightScale::Result &&
                                                    arg.to == "rs-mapper-1-1" &&
                                                    arg.results == ['hello', 'you']},
                                          hsh(:persistent => true, :mandatory => true)).once
    @dispatcher.dispatch(req, @header)
  end

  it "should handle custom prefixes" do
    @registry.register(Foo.new, 'umbongo')
    req = RightScale::Request.new('/umbongo/bar', 'you')
    res = @dispatcher.dispatch(req, @header)
    res.should(be_kind_of(RightScale::Result))
    res.token.should == req.token
    res.results.should == ['hello', 'you']
  end

  it "should call the on_exception callback if something goes wrong" do
    flexmock(RightScale::Log).should_receive(:error).once
    req = RightScale::Request.new('/foo/i_kill_you', nil)
    flexmock(@actor).should_receive(:handle_exception).with(:i_kill_you, req, Exception).once
    res = @dispatcher.dispatch(req, @header)
    res.results.error?.should be_true
    (res.results.content =~ /Could not handle \/foo\/i_kill_you request/).should be_true
  end

  it "should call on_exception Procs defined in a subclass with the correct arguments" do
    flexmock(RightScale::Log).should_receive(:error).once
    actor = Bar.new
    @registry.register(actor, nil)
    req = RightScale::Request.new('/bar/i_kill_you', nil)
    @dispatcher.dispatch(req, @header)
    called_with = actor.instance_variable_get("@called_with")
    called_with[0].should == :i_kill_you
    called_with[1].should == req
    called_with[2].should be_kind_of(RuntimeError)
    called_with[2].message.should == 'I kill you!'
  end

  it "should call on_exception Procs defined in a subclass in the scope of the actor" do
    flexmock(RightScale::Log).should_receive(:error).once
    actor = Bar.new
    @registry.register(actor, nil)
    req = RightScale::Request.new('/bar/i_kill_you', nil)
    @dispatcher.dispatch(req, @header)
    actor.instance_variable_get("@scope").should == actor
  end

  it "should log error if something goes wrong" do
    RightScale::Log.should_receive(:error).once
    req = RightScale::Request.new('/foo/i_kill_you', nil)
    @dispatcher.dispatch(req, @header)
  end

  it "should reject requests whose time-to-live has expired" do
    flexmock(Time).should_receive(:now).and_return(Time.at(1000000)).by_default
    flexmock(RightScale::Log).should_receive(:info).once.with(on {|arg| arg =~ /REJECT EXPIRED.*TTL 2 sec ago/})
    @broker.should_receive(:publish).never
    @dispatcher = RightScale::Dispatcher.new(@agent, @cache)
    @dispatcher.em = EMMock
    req = RightScale::Push.new('/foo/bar', 'you', :expires_at => @now.to_i + 8)
    flexmock(Time).should_receive(:now).and_return(@now += 10)
    @dispatcher.dispatch(req, @header).should be_nil
  end

  it "should send non-delivery result if Request is rejected because its time-to-live has expired" do
    flexmock(Time).should_receive(:now).and_return(Time.at(1000000)).by_default
    flexmock(RightScale::Log).should_receive(:info).once.with(on {|arg| arg =~ /REJECT EXPIRED/})
    @broker.should_receive(:publish).with(hsh(:name => @response_queue),
                                          on {|arg| arg.class == RightScale::Result &&
                                                    arg.to == @response_queue &&
                                                    arg.results.non_delivery? &&
                                                    arg.results.content == RightScale::OperationResult::TTL_EXPIRATION},
                                          hsh(:persistent => true, :mandatory => true)).once
    @dispatcher = RightScale::Dispatcher.new(@agent, @cache)
    @dispatcher.em = EMMock
    req = RightScale::Request.new('/foo/bar', 'you', {:reply_to => @response_queue, :expires_at => @now.to_i + 8})
    flexmock(Time).should_receive(:now).and_return(@now += 10)
    @dispatcher.dispatch(req, @header).should be_nil
  end

  it "should send error result instead of non-delivery if agent does not know about non-delivery" do
    flexmock(Time).should_receive(:now).and_return(Time.at(1000000)).by_default
    flexmock(RightScale::Log).should_receive(:info).once.with(on {|arg| arg =~ /REJECT EXPIRED/})
    @broker.should_receive(:publish).with(hsh(:name => @response_queue),
                                          on {|arg| arg.class == RightScale::Result &&
                                                    arg.to == "rs-mapper-1-1" &&
                                                    arg.results.error? &&
                                                    arg.results.content =~ /Could not deliver/},
                                          hsh(:persistent => true, :mandatory => true)).once
    @dispatcher = RightScale::Dispatcher.new(@agent, @cache)
    @dispatcher.em = EMMock
    req = RightScale::Request.new('/foo/bar', 'you', {:reply_to => "rs-mapper-1-1", :expires_at => @now.to_i + 8}, [12, 13])
    flexmock(Time).should_receive(:now).and_return(@now += 10)
    @dispatcher.dispatch(req, @header).should be_nil
  end

  it "should not reject requests whose time-to-live has not expired" do
    flexmock(Time).should_receive(:now).and_return(Time.at(1000000)).by_default
    @dispatcher = RightScale::Dispatcher.new(@agent, @cache)
    @dispatcher.em = EMMock
    req = RightScale::Request.new('/foo/bar', 'you', :expires_at => @now.to_i + 11)
    flexmock(Time).should_receive(:now).and_return(@now += 10)
    res = @dispatcher.dispatch(req, @header)
    res.should(be_kind_of(RightScale::Result))
    res.token.should == req.token
    res.results.should == ['hello', 'you']
  end

  it "should not check age of requests with time-to-live check disabled" do
    @dispatcher = RightScale::Dispatcher.new(@agent, @cache)
    @dispatcher.em = EMMock
    req = RightScale::Request.new('/foo/bar', 'you', :expires_at => 0)
    res = @dispatcher.dispatch(req, @header)
    res.should(be_kind_of(RightScale::Result))
    res.token.should == req.token
    res.results.should == ['hello', 'you']
  end

  it "should reject duplicate requests" do
    flexmock(RightScale::Log).should_receive(:info).once.with(on {|arg| arg =~ /REJECT DUP/})
    EM.run do
      @dispatcher = RightScale::Dispatcher.new(@agent, @cache)
      @dispatcher.em = EMMock
      req = RightScale::Request.new('/foo/bar_non', 1, :token => "try")
      @cache.store(req.token, nil)
      @dispatcher.dispatch(req, @header).should be_nil
      EM.stop
    end
  end

  it "should reject duplicate retry requests" do
    flexmock(RightScale::Log).should_receive(:info).once.with(on {|arg| arg =~ /REJECT RETRY DUP/})
    EM.run do
      @dispatcher = RightScale::Dispatcher.new(@agent, @cache)
      @dispatcher.em = EMMock
      req = RightScale::Request.new('/foo/bar_non', 1, :token => "try")
      req.tries.concat(["try1", "try2"])
      @cache.store("try2", nil)
      @dispatcher.dispatch(req, @header).should be_nil
      EM.stop
    end
  end

  it "should not reject non-duplicate requests" do
    EM.run do
      @dispatcher = RightScale::Dispatcher.new(@agent, @cache)
      @dispatcher.em = EMMock
      req = RightScale::Request.new('/foo/bar_non', 1, :token => "try")
      req.tries.concat(["try1", "try2"])
      @cache.store("try3", nil)
      @dispatcher.dispatch(req, @header).should_not be_nil
      EM.stop
    end
  end

  it "should not reject duplicate idempotent requests" do
    EM.run do
      @dispatcher = RightScale::Dispatcher.new(@agent, @cache)
      @dispatcher.em = EMMock
      req = RightScale::Request.new('/foo/bar', 'you', :token => "try")
      @cache.store(req.token, nil)
      @dispatcher.dispatch(req, @header).should_not be_nil
      EM.stop
    end
  end

  it "should not check for duplicates if duplicate checking is disabled" do
    EM.run do
      @dispatcher = RightScale::Dispatcher.new(@agent, dispatched_cache = nil)
      @dispatcher.em = EMMock
      req = RightScale::Request.new('/foo/bar_non', 1, :token => "try")
      req.tries.concat(["try1", "try2"])
      @dispatcher.instance_variable_get(:@dispatched_cache).should be_nil
      @dispatcher.dispatch(req, @header).should_not be_nil
      EM.stop
    end
  end

  it "should not check for duplicates if actor method is idempotent" do
    EM.run do
      @dispatcher = RightScale::Dispatcher.new(@agent, dispatched_cache = nil)
      @dispatcher.em = EMMock
      req = RightScale::Request.new('/foo/bar', 1, :token => "try")
      req.tries.concat(["try1", "try2"])
      @dispatcher.instance_variable_get(:@dispatched_cache).should be_nil
      @dispatcher.dispatch(req, @header).should_not be_nil
      EM.stop
    end
  end

  it "should return dispatch age of youngest unfinished request" do
    @header.should_receive(:ack).never
    @dispatcher.em = EMMockNoCallback
    @dispatcher.dispatch_age.should be_nil
    @dispatcher.dispatch(RightScale::Push.new('/foo/bar', 'you'), @header)
    @dispatcher.dispatch_age.should == 0
    @dispatcher.dispatch(RightScale::Request.new('/foo/bar', 'you'), @header)
    flexmock(Time).should_receive(:now).and_return(@now += 100)
    @dispatcher.dispatch_age.should == 100
  end

  it "should return dispatch age of nil if all requests finished" do
    @dispatcher.dispatch_age.should be_nil
    @dispatcher.dispatch(RightScale::Request.new('/foo/bar', 'you'), @header)
    flexmock(Time).should_receive(:now).and_return(@now += 100)
    @dispatcher.dispatch_age.should be_nil
  end

  it "should ack request even if fail while dispatching" do
    RightScale::Log.should_receive(:error).and_raise(Exception).once
    req = RightScale::Request.new('/foo/i_kill_you', nil)
    lambda { @dispatcher.dispatch(req, @header) }.should raise_error(Exception)
  end

  it "should ack request even if fail while doing final setup for processing request" do
    @dispatcher.em = EMMock
    flexmock(EMMock).should_receive(:defer).and_raise(Exception).once
    req = RightScale::Request.new('/foo/bar', 'you')
    lambda { @dispatcher.dispatch(req, @header) }.should raise_error(Exception)
  end

end # RightScale::Dispatcher
