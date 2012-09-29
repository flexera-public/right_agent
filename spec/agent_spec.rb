#
# Copyright (c) 2009-2012 RightScale Inc
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

def run_in_em(stop_event_loop = true)
  EM.run do
    yield
    EM.stop_event_loop if stop_event_loop
  end
end

describe RightScale::Agent do

  include FlexMock::ArgumentTypes

  describe "Default Option" do

    before(:all) do
      @log = flexmock(RightScale::Log)
      @log.should_receive(:error).by_default.and_return { |m| raise RightScale::Log.format(*m) }
      flexmock(EM).should_receive(:next_tick).and_yield
      flexmock(EM).should_receive(:add_timer).and_yield
      @timer = flexmock("timer")
      flexmock(EM::Timer).should_receive(:new).and_return(@timer)
      flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@timer)
      @timer.should_receive(:cancel)
      @broker = flexmock("broker", :subscribe => ["b1"], :publish => ["b1"], :prefetch => true,
                         :all => ["b1"], :connected => ["b1"], :failed => [], :close_one => true,
                         :non_delivery => true).by_default
      @broker.should_receive(:connection_status).and_yield(:connected)
      flexmock(RightAMQP::HABrokerClient).should_receive(:new).and_return(@broker)
      @history = flexmock("history")
      @history.should_receive(:update).and_return(true).by_default
      flexmock(RightScale::History).should_receive(:new).and_return(@history)
      flexmock(RightScale::PidFile).should_receive(:new).
              and_return(flexmock("pid file", :check=>true, :write=>true, :remove=>true))
      @identity = "rs-instance-123-1"
      @agent = RightScale::Agent.new(:identity => @identity)
      flexmock(@agent).should_receive(:load_actors).and_return(true)
      @agent.run
    end

    after(:each) do
      FileUtils.rm_rf(File.normalize_path(File.join(@agent.options[:root_dir], 'config.yml'))) if @agent
    end

    it "for daemonize is false" do
      @agent.options.should include(:daemonize)
      @agent.options[:daemonize].should == false
    end

    it "for console is false" do
      @agent.options.should include(:console)
      @agent.options[:console].should == false
    end

    it "for user is agent" do
      @agent.options.should include(:user)
      @agent.options[:user].should == "agent"
    end

    it "for pass(word) is testing" do
      @agent.options.should include(:pass)
      @agent.options[:pass].should == "testing"
    end

    it "for secure is true" do
      @agent.options.should include(:secure)
      @agent.options[:secure].should == true
    end

    it "for log_level is info" do
      @agent.options.should include(:log_level)
      @agent.options[:log_level].should == :info
    end

    it "for vhost is /right_net" do
      @agent.options.should include(:vhost)
      @agent.options[:vhost].should == "/right_net"
    end

    it "for root_dir is #{Dir.pwd}" do
      @agent.options.should include(:root_dir)
      @agent.options[:root_dir].should == Dir.pwd
    end

    it "for heartbeat is 60" do
      @agent.options.should include(:heartbeat)
      @agent.options[:heartbeat].should == 60
    end

  end

  describe "Options from config.yml" do

    before(:all) do
      @agent = RightScale::Agent.new(:identity => @identity)
      flexmock(@agent).should_receive(:load_actors).and_return(true)
      @agent.run
    end

    after(:each) do
      FileUtils.rm_rf(File.normalize_path(File.join(@agent.options[:root_dir], 'config.yml'))) if @agent
    end
 
  end

  describe "Passed in Options" do

    before(:each) do
      @log = flexmock(RightScale::Log)
      @log.should_receive(:error).never.by_default
      flexmock(EM).should_receive(:next_tick).and_yield
      flexmock(EM).should_receive(:add_timer).and_yield
      @timer = flexmock("timer")
      flexmock(EM::Timer).should_receive(:new).and_return(@timer)
      flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@timer)
      @timer.should_receive(:cancel)
      @broker = flexmock("broker", :subscribe => ["b1"], :publish => ["b1"], :prefetch => true,
                         :connected => ["b1"], :failed => [], :all => ["b0", "b1"],
                         :non_delivery => true).by_default
      @broker.should_receive(:connection_status).and_yield(:connected)
      flexmock(RightAMQP::HABrokerClient).should_receive(:new).and_return(@broker)
      @history = flexmock("history")
      @history.should_receive(:update).and_return(true).by_default
      flexmock(RightScale::History).should_receive(:new).and_return(@history)
      flexmock(RightScale::PidFile).should_receive(:new).
              and_return(flexmock("pid file", :check=>true, :write=>true, :remove=>true))
      @identity = "rs-instance-123-1"
      @agent = nil
    end

    after(:each) do
      FileUtils.rm_rf(File.normalize_path(File.join(@agent.options[:root_dir], 'config.yml'))) if @agent
    end

    it "for user should override default (agent)" do
      @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
      @agent.options.should include(:user)
      @agent.options[:user].should == "me"
    end

    it "for pass(word) should override default (testing)" do
      @agent = RightScale::Agent.new(:pass => "secret", :identity => @identity)
      @agent.options.should include(:pass)
      @agent.options[:pass].should == "secret"
    end

    it "for secure should override default (false)" do
      @agent = RightScale::Agent.new(:secure => true, :identity => @identity)
      @agent.options.should include(:secure)
      @agent.options[:secure].should == true
    end

    it "for host should override default (localhost)" do
      @agent = RightScale::Agent.new(:host => "127.0.0.1", :identity => @identity)
      @agent.options.should include(:host)
      @agent.options[:host].should == "127.0.0.1"
    end

    it "for log_dir" do
      # testing path, remove it before the test to verify the directory is
      # actually created
      test_log_path = File.normalize_path(File.join(Dir.tmpdir, "right_net", "testing"))
      FileUtils.rm_rf(test_log_path)

      @agent = RightScale::Agent.new(:log_dir => File.normalize_path(File.join(Dir.tmpdir, "right_net", "testing")),
                                    :identity => @identity)

      # passing log_dir will cause log_path to be set to the same value and the
      # directory wil be created
      @agent.options.should include(:log_dir)
      @agent.options[:log_dir].should == test_log_path

      @agent.options.should include(:log_path)
      @agent.options[:log_path].should == test_log_path

      File.directory?(@agent.options[:log_path]).should == true
    end

    it "for log_level should override default (info)" do
      @agent = RightScale::Agent.new(:log_level => :debug, :identity => @identity)
      @agent.options.should include(:log_level)
      @agent.options[:log_level].should == :debug
    end

    it "for vhost should override default (/right_net)" do
      @agent = RightScale::Agent.new(:vhost => "/virtual_host", :identity => @identity)
      @agent.options.should include(:vhost)
      @agent.options[:vhost].should == "/virtual_host"
    end

    it "for ping_time should override default (15)" do
      @agent = RightScale::Agent.new(:ping_time => 5, :identity => @identity)
      @agent.options.should include(:ping_time)
      @agent.options[:ping_time].should == 5
    end

    it "for heartbeat should override default (60)" do
      @agent = RightScale::Agent.new(:heartbeat => 45, :identity => @identity)
      @agent.options.should include(:heartbeat)
      @agent.options[:heartbeat].should == 45
    end

    it "for root_dir should override default (#{File.dirname(__FILE__)})" do
      root_dir = File.normalize_path(File.join(File.dirname(__FILE__), '..', '..'))
      @agent = RightScale::Agent.new(:root_dir => root_dir, :identity => @identity)
      @agent.options.should include(:root_dir)
      @agent.options[:root_dir].should == root_dir
    end

    it "for a single tag should result in the agent's tags being set" do
      @agent = RightScale::Agent.new(:tag => "sample_tag", :identity => @identity)
      @agent.tags.should include("sample_tag")
    end

    it "for multiple tags should result in the agent's tags being set" do
      @agent = RightScale::Agent.new(:tag => ["sample_tag_1", "sample_tag_2"], :identity => @identity)
      @agent.tags.should include("sample_tag_1")
      @agent.tags.should include("sample_tag_2")
    end

  end

  describe "" do

    before(:each) do
      @log = flexmock(RightScale::Log)
      @log.should_receive(:error).by_default.and_return { |m| raise RightScale::Log.format(*m) }
      flexmock(EM).should_receive(:next_tick).and_yield
      flexmock(EM).should_receive(:add_timer).and_yield
      @timer = flexmock("timer")
      flexmock(EM::Timer).should_receive(:new).and_return(@timer).by_default
      @timer.should_receive(:cancel).by_default
      @periodic_timer = flexmock("timer")
      flexmock(EM::PeriodicTimer).should_receive(:new).and_return(@periodic_timer)
      @periodic_timer.should_receive(:cancel).by_default
      @broker_id = "rs-broker-123-1"
      @broker_id2 = "rs-broker-123-2"
      @broker_ids = [@broker_id, @broker_id2]
      @broker = flexmock("broker", :subscribe => @broker_ids, :publish => @broker_ids.first(1), :prefetch => true,
                         :all => @broker_ids, :connected => @broker_ids.first(1), :failed => @broker_ids.last(1),
                         :unusable => @broker_ids.last(1), :close_one => true, :non_delivery => true,
                         :stats => "", :status => "status", :hosts => ["123"], :ports => [1, 2], :get => true,
                         :alias_ => "b1", :aliases => ["b1"]).by_default
      @broker.should_receive(:connection_status).and_yield(:connected).by_default
      @broker.should_receive(:identity_parts).with(@broker_id).and_return(["123", 1, 0, 0])
      @broker.should_receive(:identity_parts).with(@broker_id2).and_return(["123", 2, 1, 1])
      flexmock(RightAMQP::HABrokerClient).should_receive(:new).and_return(@broker)
      flexmock(RightScale::PidFile).should_receive(:new).
              and_return(flexmock("pid file", :check=>true, :write=>true, :remove=>true))
      @history = flexmock("history")
      @history.should_receive(:update).and_return(true).by_default
      @history.should_receive(:analyze_service).and_return({}).by_default
      flexmock(RightScale::History).should_receive(:new).and_return(@history)
      @header = flexmock("amqp header")
      @header.should_receive(:ack).by_default
      @sender = flexmock("sender", :pending_requests => [], :request_age => nil,
                         :message_received => true, :stats => "").by_default
      @sender.should_receive(:terminate).and_return([0, 0]).by_default
      flexmock(RightScale::Sender).should_receive(:new).and_return(@sender)
      @dispatcher = flexmock("dispatcher", :dispatch_age => nil, :dispatch => true, :stats => "").by_default
      flexmock(RightScale::Dispatcher).should_receive(:new).and_return(@dispatcher)
      @identity = "rs-instance-123-1"
      @agent = RightScale::Agent.new(:user => "tester", :identity => @identity)
      flexmock(@agent).should_receive(:load_actors).and_return(true)
    end

    after(:each) do
      FileUtils.rm_rf(File.normalize_path(File.join(@agent.options[:root_dir], 'config.yml'))) if @agent
    end

    describe "Setting up queues" do

      it "should subscribe to identity queue using identity exchange" do
        run_in_em do
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, Hash, Proc).and_return(@broker_ids).once
          @agent.run
        end
      end

      it "should try to finish setup by connecting to failed brokers when check status" do
        run_in_em do
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, hsh(:brokers => nil), Proc).
                                             and_return(@broker_ids.first(1)).once
          @agent.run
          @agent.instance_variable_get(:@remaining_setup).should == {:setup_identity_queue => @broker_ids.last(1)}
          @sender.should_receive(:send_push).with("/registrar/connect", {:agent_identity => @identity, :host => "123",
                                                                         :port => 2, :id => 1, :priority => 1}).once
          @agent.__send__(:check_status)
        end
      end

      it "should try to connect to broker when requested" do
        run_in_em do
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, hsh(:brokers => nil), Proc).
                                             and_return(@broker_ids.first(1)).once
          @agent.run
          @broker.should_receive(:connect).with("123", 2, 1, 1, false, Proc).once
          @agent.connect("123", 2, 1, 1)
        end
      end

      it "should setup queues and update configuration when successfully connect to broker" do
        run_in_em do
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, hsh(:brokers => nil), Proc).
                                             and_return(@broker_ids.first(1)).once
          @agent.run
          @broker.should_receive(:connect).with("123", 2, 1, 1, false, Proc).and_yield(@broker_ids.last).once
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, hsh(:brokers => @broker_ids.last(1)), Proc).
                                             and_return(@broker_ids.last(1)).once
          flexmock(@agent).should_receive(:update_configuration).with(:host => ["123"], :port => [1, 2]).and_return(true).once
          @agent.connect("123", 2, 1, 1)
        end
      end

      it "should update history with start and then run when agent is for service" do
        @history.should_receive(:update).with("start").and_return(true).ordered.once
        flexmock(@agent).should_receive(:setup_queues).ordered.once
        @history.should_receive(:update).with("run").and_return(true).ordered.once
        @agent.run
      end

      it "should log error if fail to connect to broker" do
        run_in_em do
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, hsh(:brokers => nil), Proc).
                                             and_return(@broker_ids.first(1)).once
          @agent.run
          @broker.should_receive(:connect).with("123", 2, 1, 1, false, Proc).and_yield(@broker_ids.last).once
          @broker.should_receive(:connection_status).and_yield(:failed)
          @log.should_receive(:error).with(/Failed to connect to broker/).once
          flexmock(@agent).should_receive(:update_configuration).never
          @agent.connect("123", 2, 1, 1)
        end
      end

      it "should disconnect from broker when requested" do
        run_in_em do
          @broker.should_receive(:connected).and_return(@broker_ids)
          @broker.should_receive(:failed).and_return([])
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, hsh(:brokers => nil), Proc).
                                             and_return(@broker_ids).once
          @agent.run
          @broker.should_receive(:close_one).with(@broker_ids.last).once
          @agent.disconnect("123", 2)
        end
      end

      it "should remove broker from configuration if requested" do
        run_in_em do
          @broker.should_receive(:connected).and_return(@broker_ids)
          @broker.should_receive(:failed).and_return([])
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, hsh(:brokers => nil), Proc).
                                             and_return(@broker_ids).once
          @agent.run
          @broker.should_receive(:remove).with("123", 2, Proc).and_yield(@broker_ids.last).once
          @broker.should_receive(:ports).and_return([1])
          flexmock(@agent).should_receive(:update_configuration).with(:host => ["123"], :port => [1]).and_return(true).once
          @agent.disconnect("123", 2, remove = true)
        end
      end

      it "should not disconnect broker if it is the last connected broker" do
        run_in_em do
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, hsh(:brokers => nil), Proc).
                                             and_return(@broker_ids.first(1)).once
          @agent.run
          @broker.should_receive(:remove).never
          @broker.should_receive(:close_one).never
          flexmock(@agent).should_receive(:update_configuration).never
          @log.should_receive(:error).with(/Not disconnecting.*last connected broker/).once
          @agent.disconnect("123", 1)
        end
      end

      it "should declare broker connection unusable if requested to do so" do
        run_in_em do
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, Hash, Proc).and_return(@broker_ids).once
          @agent.run
          @broker.should_receive(:declare_unusable).with(@broker_ids.last(1)).once
          @agent.connect_failed(@broker_ids.last(1))
        end
      end

      it "should not declare a broker connection unusable if currently connected" do
        run_in_em do
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, Hash, Proc).and_return(@broker_ids).once
          @agent.run
          @broker.should_receive(:declare_unusable).with([]).once
          @agent.connect_failed(@broker_ids.first(1))
        end
      end

    end

    describe "Handling messages" do
  
      it "should use dispatcher to handle requests" do
        run_in_em do
          request = RightScale::Request.new("/foo/bar", "payload")
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, Hash, Proc).
                                             and_return(@broker_ids).and_yield(@broker_id, request, @header).once
          @dispatcher.should_receive(:dispatch).with(request, @header).once
          @agent.run
        end
      end

      it "should use sender to handle results" do
        run_in_em do
          result = RightScale::Result.new("token", "to", "results", "from")
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, Hash, Proc).
                                             and_return(@broker_ids).and_yield(@broker_id, result, @header).once
          @sender.should_receive(:handle_response).with(result, @header).once
          @agent.run
        end
      end

      it "should notify sender when a message is received" do
        run_in_em do
          result = RightScale::Result.new("token", "to", "results", "from")
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, Hash, Proc).
                                             and_return(@broker_ids).and_yield(@broker_id, result, @header).once
          @sender.should_receive(:handle_response).with(result, @header).once
          @sender.should_receive(:message_received).once
          @agent.run
        end
      end

      it "should ignore and ack unrecognized messages" do
        run_in_em do
          request = RightScale::Stats.new(nil, nil)
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, Hash, Proc).
                                             and_return(@broker_ids).and_yield(@broker_id, request, @header).once
          @dispatcher.should_receive(:dispatch).never
          @header.should_receive(:ack).once
          @agent.run
        end
      end

      it "should ignore unrecognized messages and not attempt to ack if there is no header" do
        run_in_em do
          request = RightScale::Stats.new(nil, nil)
          @broker.should_receive(:subscribe).with(hsh(:name => @identity), nil, Hash, Proc).
                                             and_return(@broker_ids).and_yield(@broker_id, request, nil).once
          @dispatcher.should_receive(:dispatch).never
          @agent.run
        end
      end

    end

    describe "Tuning heartbeat" do

      it "should tune heartbeat for all broker connections" do
        run_in_em do
          @log.should_receive(:info).with(/\[start\] Agent #{@identity} starting; time: .*$/).once
          @log.should_receive(:info).with(/Reconnecting each broker to tune heartbeat to 45/).once
          @log.should_receive(:info).with(/Tuned heartbeat to 45 seconds for broker/).twice
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          flexmock(@agent).should_receive(:update_configuration).with(:heartbeat => 45).and_return(true).once
          @agent.run
          @broker.should_receive(:heartbeat=).with(45).once
          @broker.should_receive(:connect).with("123", 1, 0, 0, true, Proc).and_yield(@broker_id).once
          @broker.should_receive(:connect).with("123", 2, 1, 1, true, Proc).and_yield(@broker_id2).once
          flexmock(@agent).should_receive(:setup_queues).with([@broker_id]).once
          flexmock(@agent).should_receive(:setup_queues).with([@broker_id2]).once
          @agent.tune_heartbeat(45).should be_nil
        end
      end

      it "should tune heartbeat for all broker connections as deferred task" do
        run_in_em do
          @log.should_receive(:info).with(/\[start\] Agent #{@identity} starting; time: .*$/).once
          @log.should_receive(:info).with(/Reconnecting each broker to tune heartbeat to 45/).once
          @log.should_receive(:info).with(/Tuned heartbeat to 45 seconds for broker/).twice
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          flexmock(@agent).should_receive(:update_configuration).with(:heartbeat => 45).and_return(true).once
          @agent.run
          @broker.should_receive(:heartbeat=).with(45).once
          @broker.should_receive(:connect).with("123", 1, 0, 0, true, Proc).and_yield(@broker_id).once
          @broker.should_receive(:connect).with("123", 2, 1, 1, true, Proc).and_yield(@broker_id2).once
          flexmock(@agent).should_receive(:setup_queues).with([@broker_id]).once
          flexmock(@agent).should_receive(:setup_queues).with([@broker_id2]).once
          flexmock(@agent).should_receive(:finish_setup)
          @agent.defer_task { @agent.tune_heartbeat(45).should be_nil }
          @agent.__send__(:check_status)
          @agent.instance_variable_get(:@deferred_tasks).should == []
        end
      end

      it "should disable heartbeat for all broker connections" do
        run_in_em do
          @log.should_receive(:info).with(/\[start\] Agent #{@identity} starting; time: .*$/).once
          @log.should_receive(:info).with(/Reconnecting each broker to tune heartbeat to 0/).once
          @log.should_receive(:info).with(/Disabled heartbeat for broker/).twice
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          flexmock(@agent).should_receive(:update_configuration).with(:heartbeat => 0).and_return(true).once
          @agent.run
          @broker.should_receive(:heartbeat=).with(0).once
          @broker.should_receive(:connect).with("123", 1, 0, 0, true, Proc).and_yield(@broker_id).once
          @broker.should_receive(:connect).with("123", 2, 1, 1, true, Proc).and_yield(@broker_id2).once
          flexmock(@agent).should_receive(:setup_queues).with([@broker_id]).once
          flexmock(@agent).should_receive(:setup_queues).with([@broker_id2]).once
          @agent.tune_heartbeat(0).should be_nil
        end
      end

      it "should log error if any broker connect attempts fail" do
        run_in_em do
          @log.should_receive(:info).with(/\[start\] Agent #{@identity} starting; time: .*$/).once
          @log.should_receive(:info).with(/Reconnecting each broker to tune heartbeat to 45/).once
          @log.should_receive(:info).with(/Tuned heartbeat to 45 seconds for broker #{@broker_id2}/).once
          @log.should_receive(:error).with("Failed to reconnect to broker #{@broker_id} to tune heartbeat", Exception, :trace).once
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          flexmock(@agent).should_receive(:update_configuration).with(:heartbeat => 45).and_return(true).once
          @agent.run
          @broker.should_receive(:heartbeat=).with(45).once
          @broker.should_receive(:connect).with("123", 1, 0, 0, true, Proc).and_raise(Exception).once
          @broker.should_receive(:connect).with("123", 2, 1, 1, true, Proc).and_yield(@broker_id2).once
          flexmock(@agent).should_receive(:setup_queues).with([@broker_id]).never
          flexmock(@agent).should_receive(:setup_queues).with([@broker_id2]).once
          @agent.tune_heartbeat(45).should == "Failed to tune heartbeat for brokers [\"#{@broker_id}\"]"
        end
      end

      it "should log error if any brokers do not connect" do
        run_in_em do
          @log.should_receive(:info).with(/\[start\] Agent #{@identity} starting; time: .*$/).once
          @log.should_receive(:info).with(/Reconnecting each broker to tune heartbeat to 45/).once
          @log.should_receive(:info).with(/Tuned heartbeat to 45 seconds for broker #{@broker_id2}/).once
          @log.should_receive(:error).with(/Failed to reconnect to broker #{@broker_id} to tune heartbeat, status/).once
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          flexmock(@agent).should_receive(:update_configuration).with(:heartbeat => 45).and_return(true).once
          @agent.run
          @broker.should_receive(:heartbeat=).with(45).once
          @broker.should_receive(:connect).with("123", 1, 0, 0, true, Proc).and_yield(@broker_id).once
          @broker.should_receive(:connect).with("123", 2, 1, 1, true, Proc).and_yield(@broker_id2).once
          @broker.should_receive(:connection_status).with({:one_off => 60, :brokers => [@broker_id]}, Proc).and_yield(:failed)
          @broker.should_receive(:connection_status).with({:one_off => 60, :brokers => [@broker_id2]}, Proc).and_yield(:connected)
          flexmock(@agent).should_receive(:setup_queues).with([@broker_id]).never
          flexmock(@agent).should_receive(:setup_queues).with([@broker_id2]).once
          @agent.tune_heartbeat(45).should be_nil
        end
      end

      it "should log error if any broker queue setup fails" do
        run_in_em do
          @log.should_receive(:info).with(/\[start\] Agent #{@identity} starting; time: .*$/).once
          @log.should_receive(:info).with(/Reconnecting each broker to tune heartbeat to 45/).once
          @log.should_receive(:info).with(/Tuned heartbeat to 45 seconds for broker #{@broker_id2}/).once
          @log.should_receive(:error).with(/Failed to setup queues for broker #{@broker_id} when tuning heartbeat/, Exception, :trace).once
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          flexmock(@agent).should_receive(:update_configuration).with(:heartbeat => 45).and_return(true).once
          @agent.run
          @broker.should_receive(:heartbeat=).with(45).once
          @broker.should_receive(:connect).with("123", 1, 0, 0, true, Proc).and_yield(@broker_id).once
          @broker.should_receive(:connect).with("123", 2, 1, 1, true, Proc).and_yield(@broker_id2).once
          flexmock(@agent).should_receive(:setup_queues).with([@broker_id]).and_raise(Exception)
          flexmock(@agent).should_receive(:setup_queues).with([@broker_id2]).once
          @agent.tune_heartbeat(45).should be_nil
        end
      end

      it "should log error if an exception is raised" do
        run_in_em do
          @log.should_receive(:error).with(/Failed tuning broker connection heartbeat/, Exception, :trace).once
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          flexmock(@agent).should_receive(:update_configuration).with(:heartbeat => 45).and_raise(Exception).once
          @agent.run
          @broker.should_receive(:heartbeat=).with(45).once
          @agent.tune_heartbeat(45).should =~ /Failed tuning broker connection heartbeat/
        end
      end

    end

    describe "Terminating" do

      it "should log error for abnormal termination" do
        run_in_em do
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          @broker.should_receive(:nil?).and_return(true)
          @log.should_receive(:error).with("[stop] Terminating because just because", nil, :trace).once
          @agent.terminate("just because")
        end
      end

      it "should log error plus exception for abnormal termination" do
        run_in_em do
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          @broker.should_receive(:nil?).and_return(true)
          @log.should_receive(:error).with(/Terminating because just because/, Exception, :trace).once
          @agent.terminate("just because", Exception.new("error"))
        end
      end

      it "should close unusable broker connections at start of termination" do
        @broker.should_receive(:unusable).and_return(["rs-broker-123-1"]).once
        @broker.should_receive(:close_one).with("rs-broker-123-1", false).once
        run_in_em do
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          @agent.run
          @agent.terminate
        end
      end

      it "should wait to terminate if there are recent unfinished requests" do
        @sender.should_receive(:terminate).and_return([1, 10]).once
        flexmock(EM::Timer).should_receive(:new).with(20, Proc).and_return(@timer).once
        run_in_em do
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          @agent.run
          @agent.terminate
        end
      end

      it "should log that terminating and then log the reason for waiting to terminate" do
        @sender.should_receive(:terminate).and_return([1, 21]).once
        flexmock(EM::Timer).should_receive(:new).with(9, Proc).and_return(@timer).once
        run_in_em do
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          @agent.run
          @log.should_receive(:info).with(/Agent rs-instance-123-1 terminating/).once
          @log.should_receive(:info).with(/Termination waiting 9 seconds for/).once
          @agent.terminate
        end
      end

      it "should not log reason for waiting to terminate if no need to wait" do
        @sender.should_receive(:terminate).and_return([0, nil]).twice
        @broker.should_receive(:close).once
        flexmock(EM::Timer).should_receive(:new).with(0, Proc).never
        run_in_em do
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          @agent.run
          @log.should_receive(:info).with(/Agent rs-instance-123-1 terminating/).once
          @log.should_receive(:info).with(/Termination waiting/).never
          @agent.terminate
        end
      end

      it "should continue with termination after waiting and log that continuing" do
        @sender.should_receive(:terminate).and_return([1, 10]).twice
        @sender.should_receive(:dump_requests).and_return(["request"]).once
        @broker.should_receive(:close).once
        flexmock(EM::Timer).should_receive(:new).with(20, Proc).and_return(@timer).and_yield.once
        run_in_em do
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          @agent.run
          @log.should_receive(:info).with(/Agent rs-instance-123-1 terminating/).once
          @log.should_receive(:info).with(/Termination waiting/).once
          @log.should_receive(:info).with(/Continuing with termination/).once
          @log.should_receive(:info).with(/The following 1 request/).once
          @agent.terminate
        end
      end

      it "should execute block after all brokers have been closed" do
        @sender.should_receive(:terminate).and_return([1, 10]).twice
        @sender.should_receive(:dump_requests).and_return(["request"]).once
        @broker.should_receive(:close).and_yield.once
        flexmock(EM::Timer).should_receive(:new).with(20, Proc).and_return(@timer).and_yield.once
        run_in_em do
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          @agent.run
          called = 0
          @agent.terminate { called += 1 }
          called.should == 1
        end
      end

      it "should stop EM if no block specified" do
        @sender.should_receive(:terminate).and_return([1, 10]).twice
        @sender.should_receive(:dump_requests).and_return(["request"]).once
        @broker.should_receive(:close).and_yield.once
        flexmock(EM::Timer).should_receive(:new).with(20, Proc).and_return(@timer).and_yield.once
        run_in_em(stop_event_loop = false) do
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          @agent.run
          @agent.terminate
        end
      end

      it "should terminate immediately if broker not initialized" do
        run_in_em do
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          @log.should_receive(:info).with("[stop] Terminating immediately").once
          @agent.terminate
        end
      end

      it "should terminate immediately if called a second time but should still execute block" do
        @sender.should_receive(:terminate).and_return([1, 10]).once
        flexmock(EM::Timer).should_receive(:new).with(20, Proc).and_return(@timer).once
        @timer.should_receive(:cancel).once
        @periodic_timer.should_receive(:cancel).once
        run_in_em do
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          @agent.run
          called = 0
          @agent.terminate { called += 1 }
          called.should == 0
          @agent.terminate { called += 1 }
          called.should == 1
        end
      end

      it "should update history with stop and graceful exit if broker not initialized" do
        run_in_em do
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          @log.should_receive(:error).once
          @history.should_receive(:update).with("stop").and_return(true).ordered.once
          @history.should_receive(:update).with("graceful exit").and_return(true).ordered.once
          @agent.terminate("just because")
        end
      end

      it "should update history with stop but not graceful exit if called a second time to terminate immediately" do
        run_in_em do
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          @agent.run
          @agent.instance_variable_set(:@terminating, true)
          @history.should_receive(:update).with("stop").and_return(true).once
          @history.should_receive(:update).with("graceful exit").never
          @agent.terminate
        end
      end

      it "should update history with stop and graceful exit if gracefully terminate" do
        run_in_em do
          @agent = RightScale::Agent.new(:user => "me", :identity => @identity)
          flexmock(@agent).should_receive(:load_actors).and_return(true)
          @agent.run
          @history.should_receive(:update).with("stop").and_return(true).ordered.once
          @history.should_receive(:update).with("graceful exit").and_return(true).ordered.once
          @agent.terminate
        end
      end

    end

  end

end
