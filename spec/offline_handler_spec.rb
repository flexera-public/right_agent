#
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

require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))

describe RightScale::OfflineHandler do

  include FlexMock::ArgumentTypes

  before(:each) do
    @vote = 0
    @restart_callback = lambda { @vote += 1 }
    @offline_stats = RightSupport::Stats::Activity.new
    @handler = RightScale::OfflineHandler.new(@restart_callback, @offline_stats)
  end

  context :initialize do
    it "sets initial state to created and mode to initializing" do
      @handler.state == :created
      @handler.mode == :initializing
      @handler.queue.size.should == 0
    end
  end

  context :init do
    it "advances state from created to initializing so that new requests get prepended to queue" do
      @handler.state.should == :created
      @handler.init.should be_true
      @handler.state.should == :initializing
    end

    it "does nothing if not in the created state" do
      @handler.init
      @handler.start
      state = @handler.state
      state.should_not == :created
      @handler.init.should be_true
      @handler.state.should == state
    end
  end

  context :start do
    it "sets state to running if in offline mode" do
      @handler.init
      flexmock(@handler).should_receive(:start_timer)
      @handler.enable
      @handler.start.should be_true
      @handler.state.should == :running
      @handler.mode.should == :offline
    end

    it "sets state to flushing and flushes if not in offline mode" do
      @handler.init
      flexmock(@handler).should_receive(:flush).once
      @handler.start.should be_true
      @handler.state.should == :flushing
      @handler.mode.should == :online
    end

    it "does nothing if not in initializing state" do
      @handler.state.should == :created
      @handler.start.should be_true
      @handler.state.should == :created
    end
  end

  context :offline? do
    it "indicates that offline when initially created" do
      @handler.offline?.should be_true
    end

    it "indicates that not offline after initialize offline queueing" do
      @handler.init
      @handler.offline?.should be_false
    end

    it "indicates that offline when offline has been enabled" do
      @handler.init
      flexmock(@handler).should_receive(:start_timer)
      @handler.enable
      @handler.offline?.should be_true
    end
  end

  context :queueing? do
    it "indicates that should queue when initially created" do
      @handler.queueing?.should be_true
    end

    it "indicates that should not queue once initialize offline queueing" do
      @handler.init
      @handler.queueing?.should be_false
    end

    it "indicates that should queue when offline has been enabled" do
      @handler.init
      flexmock(@handler).should_receive(:start_timer)
      @handler.enable
      @handler.queueing?.should be_true
    end

    it "indicates that should not queue if offline but currently flushing" do
      @handler.init
      @handler.queueing?.should be_false
      @handler.start
      @handler.queueing?.should be_false
      flexmock(@handler).should_receive(:start_timer)
      @handler.enable
      @handler.queueing?.should be_true
      flexmock(EM).should_receive(:add_timer)
      @handler.disable
      @handler.state.should == :flushing
      @handler.mode.should == :offline
      @handler.queueing?.should be_false
    end
  end

  context :enable do
    it "goes into offline mode if not offline now" do
      @handler.init
      @handler.start
      flexmock(@handler).should_receive(:start_timer)
      @handler.enable.should be_true
      @handler.state.should == :running
      @handler.mode.should == :offline
    end

    it "starts restart vote timer when after going into offline mode" do
      @handler.init
      @handler.start
      flexmock(EM::Timer).should_receive(:new).once
      @handler.enable.should be_true
    end

    it "sets state to running if was offline and now in flushing state" do
      @handler.init
      @handler.start
      flexmock(@handler).should_receive(:start_timer)
      @handler.enable
      flexmock(EM).should_receive(:add_timer)
      @handler.disable
      @handler.enable.should be_true
      @handler.state.should == :running
      @handler.mode.should == :offline
    end
  end

  context :disable do
    it "sets state to flushing and starts timer to begin flushing" do
      @handler.init
      @handler.start
      flexmock(@handler).should_receive(:start_timer)
      @handler.enable
      flexmock(@handler).should_receive(:cancel_timer).once
      flexmock(EM).should_receive(:add_timer).once
      @handler.disable.should be_true
      @handler.state.should == :flushing
    end

    it "does nothing if in created state" do
      @handler.disable.should be_true
    end

    it "does nothing if not offline" do
      @handler.init
      @handler.disable.should be_true
    end
  end

  context :queue_request do
    before(:each) do
      @kind = :send_request
      @type = "/foo/bar"
      @payload = {:pay => "load"}
      @target = "target"
      @callback = lambda { |_| }
    end

    it "queues request at head of queue if still initializing" do
      @handler.init
      @handler.queue_request(@kind, @type, @payload, "target1", @callback).should be_true
      @handler.queue.size.should == 1
      @handler.queue_request(@kind, @type, @payload, "target2", @callback).should be_true
      @handler.queue.size.should == 2
      @handler.queue.first[:target] == "target2"
    end

    it "queues request at end of queue if no longer initializing" do
      @handler.init
      @handler.start
      @handler.queue_request(@kind, @type, @payload, "target1", @callback)
      @handler.queue.size.should == 1
      @handler.queue_request(@kind, @type, @payload, "target2", @callback)
      @handler.queue.size.should == 2
      @handler.queue.first[:target] == "target1"
    end

    it "votes to restart if restart vote count has exceeded max queue length" do
      @handler.init
      @handler.start
      flexmock(@handler).should_receive(:vote_to_restart).once
      RightScale::OfflineHandler::MAX_QUEUED_REQUESTS.times do |i|
        @handler.queue_request(@kind, @type, @payload, @target, @callback)
      end
    end
  end

  context :terminate do
    it "sets state to terminating and cancels all timers" do
      @handler.init
      @handler.start
      @handler.terminate
      @handler.state.should == :terminating
    end
  end

  context :flush do
    before(:each) do
      @sender = flexmock("sender")
      flexmock(RightScale::Sender).should_receive(:instance).and_return(@sender)
      @kind = :send_request
      @type = "/foo/bar"
      @payload = {:pay => "load"}
      @target = "target"
      @result = nil
      @callback = lambda { |result| @result = result }
    end

    context "when in flushing state" do
      before(:each) do
        @handler.init
        @handler.start
        flexmock(@handler).should_receive(:start_timer)
        @handler.enable
        @handler.queue_request(:send_push, @type, @payload, @target, nil)
        @handler.queue_request(:send_request, @type, @payload, @target, @callback)
        @handler.queue.size.should == 2
        flexmock(EM).should_receive(:next_tick).and_yield.once
        @sender.should_receive(:send_push).with(@type, @payload, @target).once.ordered
        @sender.should_receive(:send_request).with(@type, @payload, @target, Proc).and_yield("result").once.ordered
        flexmock(EM).should_receive(:add_timer).and_yield.once
        log = flexmock(RightScale::Log)
        log.should_receive(:info).with(/Connection to RightNet re-established/).once.ordered
        log.should_receive(:info).with(/Starting to flush request queue/).once.ordered
        log.should_receive(:info).with(/Request queue flushed/).once.ordered
        @handler.disable.should be_true
      end

      it "submits all queued messages to the sender" do
        @handler.queue.size.should == 0
      end

      it "sets up for callback to be executed" do
        @result.should == "result"
      end

      it "changes state to running and mode to online" do
        @handler.state.should == :running
        @handler.mode.should == :online
      end
    end

    it "does nothing if not in flushing state" do
      @handler.init
      @handler.start
      @sender.should_receive(:send_push).never
      @sender.should_receive(:send_request).never
      @handler.send(:flush).should be_true
    end
  end

  context :vote_to_restart do
    it "makes a restart vote callback" do
      @handler.send(:vote_to_restart).should be_true
      @vote.should == 1
      @handler.instance_variable_get(:@restart_vote_count).should == 0
    end

    it "starts a vote timer if requested" do
      flexmock(@handler).should_receive(:start_timer).once
      @handler.send(:vote_to_restart, timer_trigger = true).should be_true
    end

    it "does nothing if there is no restart vote callback" do
      @handler = RightScale::OfflineHandler.new(restart_callback = nil, @offline_stats)
      flexmock(@handler).should_receive(:start_timer).never
      @handler.send(:vote_to_restart, timer_trigger = true).should be_true
    end
  end

  context :start_timer do
    it "starts a re-vote timer" do
      timer = flexmock("timer")
      flexmock(EM::Timer).should_receive(:new).and_return(timer).once
      @handler.send(:start_timer).should be_true
      @handler.instance_variable_get(:@restart_vote_timer).should == timer
    end

    it "does nothing if there is not restart vote callback or if terminating" do
      @handler = RightScale::OfflineHandler.new(restart_callback = nil, @offline_stats)
      flexmock(EM::Timer).should_receive(:new).never
      @handler.send(:start_timer).should be_true
    end
  end

  context :cancel_timer do
    it "cancels restart vote timer and resets the vote count" do
      timer = flexmock("timer")
      timer.should_receive(:cancel).once
      flexmock(EM::Timer).should_receive(:new).and_return(timer)
      @handler.send(:start_timer)
      @handler.send(:cancel_timer).should be_true
      @handler.instance_variable_get(:@restart_vote_timer).should be_nil
      @handler.instance_variable_get(:@restart_vote_count).should == 0
    end

    it "does nothing if the restart vote timer is not running" do
      @handler.send(:cancel_timer).should be_true
    end
  end
end
