#
# Copyright (c) 2009-2013 RightScale Inc
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

describe RightScale::ConnectivityChecker do

  include FlexMock::ArgumentTypes

  #describe "and checking connection status" do
  #  before(:each) do
  #    @broker_id = "rs-broker-host-123"
  #    @broker_ids = [@broker_id]
  #  end
  #
  #  it "should not check connection if check already in progress" do
  #    flexmock(EM::Timer).should_receive(:new).and_return(@timer).never
  #    @instance.connectivity_checker.ping_timer = true
  #    flexmock(@instance).should_receive(:publish).never
  #    @instance.connectivity_checker.check(@broker_ids)
  #  end
  #
  #  it "should publish ping to router" do
  #    flexmock(EM::Timer).should_receive(:new).and_return(@timer).once
  #    flexmock(@instance).should_receive(:publish).with(on { |request| request.type.should == "/router/ping" },
  #                                                      @broker_ids).and_return(@broker_ids).once
  #    @instance.connectivity_checker.check(@broker_id)
  #    @instance.pending_requests.size.should == 1
  #  end
  #
  #  it "should not make any connection changes if receive ping response" do
  #    flexmock(RightScale::AgentIdentity).should_receive(:generate).and_return('abc').once
  #    @timer.should_receive(:cancel).once
  #    flexmock(EM::Timer).should_receive(:new).and_return(@timer).once
  #    flexmock(@instance).should_receive(:publish).and_return(@broker_ids).once
  #    @instance.connectivity_checker.check(@broker_id)
  #    @instance.connectivity_checker.ping_timer.should == @timer
  #    @instance.pending_requests.size.should == 1
  #    @instance.pending_requests['abc'].response_handler.call(nil)
  #    @instance.connectivity_checker.ping_timer.should == nil
  #  end
  #
  #  it "should try to reconnect if ping times out repeatedly" do
  #    @log.should_receive(:warning).with(/timed out after 30 seconds/).twice
  #    @log.should_receive(:error).with(/reached maximum of 3 timeouts/).once
  #    flexmock(EM::Timer).should_receive(:new).and_yield.times(3)
  #    flexmock(@agent).should_receive(:connect).once
  #    @instance.connectivity_checker.check(@broker_id)
  #    @instance.connectivity_checker.check(@broker_id)
  #    @instance.connectivity_checker.check(@broker_id)
  #    @instance.connectivity_checker.ping_timer.should == nil
  #  end
  #
  #  it "should log error if attempt to reconnect fails" do
  #    @log.should_receive(:warning).with(/timed out after 30 seconds/).twice
  #    @log.should_receive(:error).with(/Failed to reconnect/, Exception, :trace).once
  #    flexmock(@agent).should_receive(:connect).and_raise(Exception)
  #    flexmock(EM::Timer).should_receive(:new).and_yield.times(3)
  #    @instance.connectivity_checker.check(@broker_id)
  #    @instance.connectivity_checker.check(@broker_id)
  #    @instance.connectivity_checker.check(@broker_id)
  #  end
  #end
end
