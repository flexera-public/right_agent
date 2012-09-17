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
require 'tmpdir'

describe RightScale::History do

  # Mock Time.now with well-defined interval
  def mock_time(size = 20, interval = 10)
    now = Time.at(1000000)
    list = []
    size.times { list << (now += interval) }
    flexmock(Time).should_receive(:now).and_return(*list)
  end

  before(:each) do
    @identity = "rs-agent-1-1"
    @pid = Process.pid
    @now = Time.at(1000000)
    flexmock(Time).should_receive(:now).and_return(@now).by_default
    FileUtils.mkdir_p(@test_dir = File.join(RightScale::Platform.filesystem.temp_dir, 'history_test'))
    RightScale::AgentConfig.pid_dir = @test_dir
    @history = RightScale::History.new(@identity)
  end

  after(:each) do
    FileUtils.remove_dir(@test_dir)
  end

  describe "update" do

    it "should store event in history file" do
      @history.update("some event").should be_true
      @history.load.should == [{"time" => 1000000, "pid" => @pid, "event" => "some event"}]
    end

    it "should store event in history file following previous event" do
      @history.update("some event").should be_true
      flexmock(Time).should_receive(:now).and_return(@now += 10)
      @history.update("another event").should be_true
      @history.load.should == [{"time" => 1000000, "pid" => @pid, "event" => "some event"},
                                          {"time" => 1000010, "pid" => @pid, "event" => "another event"}]
    end

  end

  describe "load" do

    it "should load no events if there is no history" do
      @history.load.should == []
    end

    it "should load events from history file" do
      @history.update("some event").should be_true
      @history.load.should == [{"time" => 1000000, "pid" => @pid, "event" => "some event"}]
    end

  end

  describe "analyze_service" do

    it "should indicate no uptime if history empty" do
      @history.analyze_service.should == {:uptime => 0, :total_uptime => 0}
    end

    it "should indicate no uptime if not yet running" do
      mock_time
      @history.update("start")
      @history.analyze_service.should == {:uptime => 0, :total_uptime => 0}
    end

    it "should measure uptime starting from last run time" do
      mock_time
      @history.update("start")
      @history.update("run")
      @history.analyze_service.should == {:uptime => 10, :total_uptime => 10}
    end

    it "should not count initial start as a restart" do
      @history.update("start")
      @history.update("run")
      @history.analyze_service.should == {:uptime => 0, :total_uptime => 0}
    end

    it "should count restarts" do
      @history.update("start")
      @history.update("stop")
      @history.update("start")
      @history.analyze_service.should == {:uptime => 0, :total_uptime => 0, :restarts => 1, :graceful_exits => 0}
    end

    it "should ignore repeated stops when counting restarts" do
      @history.update("start")
      @history.update("stop")
      @history.update("stop")
      @history.update("start")
      @history.analyze_service.should == {:uptime => 0, :total_uptime => 0, :restarts => 1, :graceful_exits => 0}
    end

    it "should record number of graceful exits if there are restarts" do
      @history.update("start")
      @history.update("run")
      @history.update("stop")
      @history.update("graceful exit")
      @history.update("start")
      @history.update("stop")
      @history.update("start")
      @history.update("run")
      @history.update("stop")
      @history.update("graceful exit")
      @history.update("start")
      @history.update("run")
      @history.analyze_service.should == {:uptime => 0, :total_uptime => 0, :restarts => 3, :graceful_exits => 2}
    end

    it "should measure total uptime across restarts and include current uptime" do
      mock_time
      @history.update("start")
      @history.update("run")
      @history.update("stop")
      @history.update("graceful exit")
      @history.update("start")
      @history.update("stop")
      @history.update("start")
      @history.update("run")
      @history.update("stop")
      @history.update("graceful exit")
      @history.update("start")
      @history.update("run")
      @history.analyze_service.should == {:uptime => 10, :total_uptime => 30, :restarts => 3, :graceful_exits => 2}
    end

    it "should count crashes" do
      @history.update("start")
      @history.update("start")
      @history.analyze_service.should == {:uptime => 0, :total_uptime => 0, :crashes => 1, :last_crash_time => 1000000}
    end

    it "should record last crash age if there are crashes" do
      mock_time
      @history.update("start")
      @history.update("start")
      @history.analyze_service.should == {:uptime => 0, :total_uptime => 0, :crashes => 1, :last_crash_time => 1000020}
    end

    it "should count restarts and crashes" do
      mock_time
      @history.update("start")
      @history.update("run")
      @history.update("stop")
      @history.update("graceful exit")
      @history.update("start")
      @history.update("start")
      @history.update("stop")
      @history.update("start")
      @history.update("run")
      @history.update("stop")
      @history.update("graceful exit")
      @history.update("start")
      @history.update("run")
      @history.update("start")
      @history.update("run")
      @history.analyze_service.should == {:uptime => 10, :total_uptime => 40, :restarts => 3, :graceful_exits => 2,
                                          :crashes => 2, :last_crash_time => 1000140}
    end

    it "should ignore unrecognized events" do
      @history.update("other event")
      @history.update("start")
      @history.update("other event")
      @history.update("stop")
      @history.update("start")
      @history.update("other event")
      @history.analyze_service.should == {:uptime => 0, :total_uptime => 0, :restarts => 1, :graceful_exits => 0}
    end

    it "should not re-analyze if there are no new events" do
      mock_time
      @history.update("start")
      @history.update("run")
      @history.analyze_service.should == {:uptime => 10, :total_uptime => 10}
      flexmock(@history).should_receive(:load).never
      @history.analyze_service
    end

    it "should update uptime and total_uptime even if do not do re-analyze" do
      mock_time
      @history.update("start")
      @history.update("run")
      @history.update("start")
      @history.update("run")
      @history.update("stop")
      @history.update("graceful exit")
      @history.update("start")
      @history.update("run")
      @history.analyze_service.should == {:uptime => 10, :total_uptime => 30, :restarts => 1, :graceful_exits => 1,
                                          :crashes => 1, :last_crash_time => 1000030}
      @history.analyze_service.should == {:uptime => 20, :total_uptime => 40, :restarts => 1, :graceful_exits => 1,
                                          :crashes => 1, :last_crash_time => 1000030}
    end

    it "should re-analyze if there was a new event since last analysis" do
      mock_time
      @history.update("start")
      @history.update("run")
      @history.analyze_service.should == {:uptime => 10, :total_uptime => 10}
      @history.instance_variable_set(:@pid, -1) # Simulate new process id following crash
      @history.update("start")
      @history.analyze_service.should == {:uptime => 0, :total_uptime => 20, :crashes => 1, :last_crash_time => 1000040}
    end

  end

end
