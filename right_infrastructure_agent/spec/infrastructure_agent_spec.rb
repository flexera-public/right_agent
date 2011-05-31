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

require File.join(File.dirname(__FILE__), '..', '..', '..', 'spec', 'spec_helper')
require File.join(File.dirname(__FILE__), '..', 'lib', 'infrastructure_agent')
require 'tmpdir'

def run_in_em(stop_event_loop = true)
  EM.run do
    yield
    EM.stop_event_loop if stop_event_loop
  end
end

describe RightScale::InfrastructureAgent do

  include FlexMock::ArgumentTypes

  before(:each) do
    flexmock(RightScale::RightLinkLog).should_receive(:error).and_return { |m| raise m[1] }.by_default
    flexmock(EM).should_receive(:add_timer).and_yield
    flexmock(EM).should_receive(:add_periodic_timer)
    flexmock(EM).should_receive(:next_tick).and_yield
    @timer = flexmock("timer")
    flexmock(EM::Timer).should_receive(:new).and_return(@timer).by_default
    @timer.should_receive(:cancel).by_default
    @broker_id = "rs-broker-123-1"
    @broker_ids = ["rs-broker-123-1", "rs-broker-123-2"]
    @broker = flexmock("broker", :subscribe => @broker_ids, :publish => @broker_ids.first(1), :prefetch => true,
                       :all => @broker_ids, :connected => @broker_ids.first(1),
                       :unusable => @broker_ids.last(1), :close_one => true, :non_delivery => true,
                       :stats => "", :identity_parts => ["123", 2, 1, 1, nil]).by_default
    @broker.should_receive(:connection_status).and_yield(:connected)
    @broker.should_receive(:failed).and_return(@broker_ids.last(1)).by_default
    flexmock(RightScale::HABrokerClient).should_receive(:new).and_return(@broker)
    flexmock(RightScale::PidFile).should_receive(:new).
            and_return(flexmock("pid file", :check=>true, :write=>true, :remove=>true))
    @mapper_proxy = flexmock("mapper_proxy", :pending_requests => [], :request_age => nil,
                             :message_received => true, :terminate => [0, 0], :stats => "").by_default
    flexmock(RightScale::MapperProxy).should_receive(:new).and_return(@mapper_proxy)
    @dispatcher = flexmock("dispatcher", :dispatch_age => nil, :dispatch => true, :stats => "").by_default
    flexmock(RightScale::Dispatcher).should_receive(:new).and_return(@dispatcher)
    @identity = "rs-core-123-1"
  end

  after(:each) do
    FileUtils.rm_rf(File.normalize_path(File.join(@agent.options[:root], 'config.yml'))) if @agent
  end

  describe "Passed in options" do

    it "for shared_queue should not be included if nil" do
      @agent = RightScale::InfrastructureAgent.start(:identity => @identity)
      @agent.options[:shared_queue].should be_nil
    end

    it "for shared_queue should be included if not nil" do
      @agent = RightScale::InfrastructureAgent.start(:shared_queue => "my_shared_queue", :identity => @identity)
      @agent.options.should include(:shared_queue)
      @agent.options[:shared_queue].should == "my_shared_queue"
    end

  end

  describe "Setting up queues" do

    it "should subscribe to identity queue using identity exchange" do
      run_in_em do
        @broker.should_receive(:subscribe).with(hsh(:name => @identity), hsh(:name => @identity), Hash, Proc).
                                           and_return(@broker_ids).once
        @agent = RightScale::InfrastructureAgent.start(:user => "tester", :identity => @identity)
      end
    end

    it "should bind identity queue to advertise exchange" do
      run_in_em do
        @broker.should_receive(:subscribe).with(Hash, Hash, hsh(:exchange2 => {:type => :fanout, :name => "advertise",
                                                :options => {:durable => true}}), Proc).and_return(@broker_ids).once
        @agent = RightScale::InfrastructureAgent.start(:user => "tester", :identity => @identity)
      end
    end

    it "should subscribe to shared queue if specified" do
      run_in_em do
        @broker.should_receive(:subscribe).with(hsh(:name => @identity), hsh(:name => @identity), Hash, Proc).
                                           and_return(@broker_ids).once
        @broker.should_receive(:subscribe).with(hsh(:name => "shared"), hsh(:name => "shared"), Hash, Proc).
                                           and_return(@broker_ids).once
        @agent = RightScale::InfrastructureAgent.start(:user => "tester", :identity => @identity, :shared_queue => "shared")
      end
    end

    it "should advertise services after setting up queues" do
      run_in_em do
        @broker.should_receive(:subscribe).with(Hash, Hash, hsh(:exchange2 => {:type => :fanout, :name => "advertise",
                                                :options => {:durable => true}}), Proc).and_return(@broker_ids).once
        @broker.should_receive(:publish).with(hsh(:name => "shared-registration"), RightScale::Register, Hash).once
        @agent = RightScale::InfrastructureAgent.start(:user => "tester", :identity => @identity)
      end
    end

    it "should only allow requests to be received on shared queue" do
      run_in_em do
        @broker.should_receive(:subscribe).with(hsh(:name => @identity), hsh(:name => @identity), Hash, Proc).
                                           and_return(@broker_ids).once
        filter = [:from, :tags, :tries, :persistent]
        @broker.should_receive(:subscribe).with(hsh(:name => "shared"), hsh(:name => "shared"),
                                                {:ack => true, RightScale::Request => filter, RightScale::Push => filter,
                                                :category => "request", :brokers => nil}, Proc).and_return(@broker_ids).once
        @agent = RightScale::InfrastructureAgent.start(:user => "tester", :identity => @identity, :shared_queue => "shared")
      end
    end

    it "should try to finish setup by subscribing to remaining queues when check status" do
      run_in_em do
        @broker.should_receive(:subscribe).with(hsh(:name => @identity), hsh(:name => @identity),
                                                hsh(:brokers => nil), Proc).
                                           and_return(@broker_ids.first(1)).once
        @broker.should_receive(:subscribe).with(hsh(:name => "shared"), hsh(:name => "shared"),
                                                hsh(:brokers => nil), Proc).
                                           and_return(@broker_ids.first(1)).once
        @agent = RightScale::InfrastructureAgent.start(:user => "tester", :identity => @identity, :shared_queue => "shared")
        @agent.instance_variable_get(:@remaining_setup).should == {:setup_identity_queue => @broker_ids.last(1),
                                                                   :setup_shared_queue => @broker_ids.last(1)}
        @broker.should_receive(:connected).and_return(@broker_ids)
        @broker.should_receive(:failed).and_return([])
        @broker.should_receive(:subscribe).with(hsh(:name => @identity), hsh(:name => @identity),
                                                hsh(:brokers => @broker_ids.last(1)), Proc).
                                           and_return(@broker_ids.last(1)).once
        @broker.should_receive(:subscribe).with(hsh(:name => "shared"), hsh(:name => "shared"),
                                                hsh(:brokers => @broker_ids.last(1)), Proc).
                                           and_return(@broker_ids.last(1)).once
        flexmock(@agent).should_receive(:connect).never
        @agent.__send__(:check_status)
        @agent.instance_variable_get(:@remaining_setup).should == {:setup_identity_queue => [],
                                                                   :setup_shared_queue => []}
      end
    end

    it "should try to finish setup by connecting to failed brokers when check status" do
      run_in_em do
        @broker.should_receive(:subscribe).with(hsh(:name => @identity), hsh(:name => @identity),
                                                hsh(:brokers => nil), Proc).
                                           and_return(@broker_ids.first(1)).once
        @broker.should_receive(:subscribe).with(hsh(:name => "shared"), hsh(:name => "shared"),
                                                hsh(:brokers => nil), Proc).
                                           and_return(@broker_ids.first(1)).once
        @agent = RightScale::InfrastructureAgent.start(:user => "tester", :identity => @identity, :shared_queue => "shared")
        @agent.instance_variable_get(:@remaining_setup).should == {:setup_identity_queue => @broker_ids.last(1),
                                                                   :setup_shared_queue => @broker_ids.last(1)}
        @broker.should_receive(:subscribe).with(hsh(:name => @identity), hsh(:name => @identity),
                                                hsh(:brokers => @broker_ids.last(1)), Proc).
                                           and_return([]).once
        @broker.should_receive(:subscribe).with(hsh(:name => "shared"), hsh(:name => "shared"),
                                                hsh(:brokers => @broker_ids.last(1)), Proc).
                                           and_return([]).once
        flexmock(@agent).should_receive(:connect).with("123", 2, 1, 1, nil).once
        @agent.__send__(:check_status)
      end
    end

    it "should advertise services periodically" do
      run_in_em do
        @broker.should_receive(:failed).and_return([])
        @agent = RightScale::InfrastructureAgent.start(:user => "tester", :identity => @identity, :shared_queue => "shared",
                                                       :check_interval => 1, :advertise_interval => 4)
        flexmock(@agent).should_receive(:advertise_services).twice
        @agent.__send__(:check_status)
        @agent.__send__(:check_status)
        @agent.__send__(:check_status)
        @agent.__send__(:check_status)
        @agent.__send__(:check_status)
        @agent.__send__(:check_status)
        @agent.__send__(:check_status)
        @agent.__send__(:check_status)
      end
    end

  end

  describe "Handling messages" do

    it "should use dispatcher to handle requests" do
      run_in_em do
        request = RightScale::Request.new("/foo/bar", "payload")
        @broker.should_receive(:subscribe).with(hsh(:name => @identity), hsh(:name => @identity), Hash, Proc).
                                           and_return(@broker_ids).and_yield(@broker_id, request).once
        @dispatcher.should_receive(:dispatch).with(request).once
        @agent = RightScale::InfrastructureAgent.start(:user => "tester", :identity => @identity)
      end
    end

    it "should use mapper proxy to handle results" do
      run_in_em do
        result = RightScale::Result.new("token", "to", "results", "from")
        @broker.should_receive(:subscribe).with(hsh(:name => @identity), hsh(:name => @identity), Hash, Proc).
                                           and_return(@broker_ids).and_yield(@broker_id, result).once
        @mapper_proxy.should_receive(:handle_response).with(result).once
        @agent = RightScale::InfrastructureAgent.start(:user => "tester", :identity => @identity)
      end
    end

    it "should advertise services when asked to advertise" do
      run_in_em do
        advertise = RightScale::Advertise.new
        @broker.should_receive(:subscribe).with(hsh(:name => @identity), hsh(:name => @identity), Hash, Proc).
                                           and_return(@broker_ids).and_yield(@broker_id, advertise).once
        @broker.should_receive(:publish).with(hsh(:name => "shared-registration"), RightScale::Register, Hash).twice
        @agent = RightScale::InfrastructureAgent.start(:user => "tester", :identity => @identity)
      end
    end

    it "should notify mapper proxy when a message is received on identity queue" do
      run_in_em do
        result = RightScale::Result.new("token", "to", "results", "from")
        @broker.should_receive(:subscribe).with(hsh(:name => @identity), hsh(:name => @identity), Hash, Proc).
                                           and_return(@broker_ids).and_yield(@broker_id, result).once
        @mapper_proxy.should_receive(:handle_response).with(result).once
        @mapper_proxy.should_receive(:message_received).once
        @agent = RightScale::InfrastructureAgent.start(:user => "tester", :identity => @identity)
      end
    end

    it "should notify mapper proxy when a message is received on shared queue" do
      run_in_em do
        request = RightScale::Push.new("/foo/bar", "payload")
        @broker.should_receive(:subscribe).with(hsh(:name => @identity), hsh(:name => @identity), Hash, Proc).
                                           and_return(@broker_ids).once
        @broker.should_receive(:subscribe).with(hsh(:name => "shared"), hsh(:name => "shared"), Hash, Proc).
                                           and_return(@broker_ids).and_yield(@broker_id, request).once
        @dispatcher.should_receive(:dispatch).with(request, true).once
        @mapper_proxy.should_receive(:message_received).once
        @agent = RightScale::InfrastructureAgent.start(:user => "tester", :identity => @identity, :shared_queue => "shared")
      end
    end

  end

  describe "Terminating" do

    it "should unregister from mapper" do
      run_in_em do
        @agent = RightScale::InfrastructureAgent.new(:user => "tester", :identity => @identity)
        @agent.run
        @broker.should_receive(:publish).with(hsh(:name => "shared-registration"), RightScale::UnRegister, Hash).once
        @broker.should_receive(:unsubscribe).never
        @agent.terminate
      end
    end

    it "should only unregister from mapper once" do
      run_in_em do
        @agent = RightScale::InfrastructureAgent.new(:user => "tester", :identity => @identity)
        @agent.run
        @broker.should_receive(:publish).with(hsh(:name => "shared-registration"), RightScale::UnRegister, Hash).once
        @broker.should_receive(:unsubscribe).never
        @agent.terminate
        @agent.terminate
      end
    end

    it "should close unusable broker connections at start of termination" do
      run_in_em do
        @agent = RightScale::InfrastructureAgent.new(:user => "tester", :identity => @identity)
        @agent.run
        @broker.should_receive(:unusable).and_return([@broker_id]).once
        @broker.should_receive(:close_one).with(@broker_id, false).once
        @broker.should_receive(:unsubscribe).never
        @agent.terminate
      end
    end

    it "should unsubscribe from shared queue" do
      run_in_em do
        @agent = RightScale::InfrastructureAgent.new(:user => "tester", :identity => @identity, :shared_queue => "shared")
        @agent.run
        @broker.should_receive(:unsubscribe).with(["shared"], 15, Proc).once
        @agent.terminate
      end
    end

  end

end
