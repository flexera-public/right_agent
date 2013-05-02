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

describe RightScale::AgentTagManager do

  include FlexMock::ArgumentTypes

  before(:each) do
    @log = flexmock(RightScale::Log)
    @log.should_receive(:error).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @identity = "rs-agent-0-0"
    @agent = flexmock("agent", :identity => @identity)
    @agent_id1 = "rs-agent-1-1"
    @agent_id2 = "rs-agent-2-2"
    @agent_ids = [@agent_id2, @agent_id3]
    @manager = RightScale::AgentTagManager.instance
    @manager.agent = @agent
    @request = flexmock("request", :run => true)
    @request.should_receive(:callback).and_yield("result").by_default
    @request.should_receive(:errback).by_default
    @request.should_receive(:raw_response).and_return("raw response").by_default
    @idempotent_request = flexmock(RightScale::IdempotentRequest)
    @tag = "some:tag=value"
    @tag1 = "other:tag=value"
    @tags = [@tag, @tag1]
    @result = nil
  end

  context :tags do

    before(:each) do
      @idempotent_request.should_receive(:new).with("/mapper/query_tags",
                                                    {:agent_identity => @identity, :agent_ids => [@identity]},
                                                    {}).and_return(@request).once.by_default
    end

    it "retrieves current agent tags" do
      @request.should_receive(:callback).and_yield({@identity => {"tags" => [@tag]}}).once
      @manager.tags { |r| @result = r }
      @result.should == [@tag]
    end

    it "returns empty array when there is no results hash" do
      @request.should_receive(:callback).and_yield({}).once
      @manager.tags { |r| @result = r }
      @result.should == []
    end

    it "returns the raw result when result is not a hash" do
      @request.should_receive(:callback).and_yield("result").once
      @manager.tags { |r| @result = r }
      @result.should == "result"
    end

    it "returns raw result when :raw option specified" do
      @request.should_receive(:callback).and_yield("result").once
      @request.should_receive(:raw_response).and_return("raw response").once
      @manager.tags(:raw => true) { |r| @result = r }
      @result.should == "raw response"
    end

    it "forwards timeout option" do
      @idempotent_request.should_receive(:new).with("/mapper/query_tags",
                                                    {:agent_identity => @identity, :agent_ids => [@identity]},
                                                    {:timeout => 9}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@identity => {"tags" => [@tag]}}).once
      @manager.tags(:timeout => 9) { |r| @result = r }
      @result.should == [@tag]
    end

    it "yields error result and logs error" do
      @log.should_receive(:error).with(/Failed to query tags/).once
      @request.should_receive(:errback).and_yield("error").once
      @request.should_receive(:callback).once
      @manager.tags { |r| @result = r }
      @result.should == "error"
    end
  end

  context :query_tags do

    it "queries for agents having individual tag" do
      @idempotent_request.should_receive(:new).with("/mapper/query_tags",
                                                    {:agent_identity => @identity, :tags => [@tag]},
                                                    {}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@identity => {"tags" => [@tag]}, @agent_id1 => {"tags" => [@tag]}}).once
      @manager.query_tags(@tag) { |r| @result = r }
      @result.should == {@identity => {"tags" => [@tag]}, @agent_id1 => {"tags" => [@tag]}}
    end

    it "queries for agents having multiple tags" do
      @idempotent_request.should_receive(:new).with("/mapper/query_tags",
                                                    {:agent_identity => @identity, :tags => @tags},
                                                    {}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@agent_id1 => {"tags" => @tags}}).once
      @manager.query_tags(@tags) { |r| @result = r }
      @result.should == {@agent_id1 => {"tags" => @tags}}
    end

    it "forwards options" do
      @idempotent_request.should_receive(:new).with("/mapper/query_tags",
                                                    {:agent_identity => @identity, :tags => @tags},
                                                    {:timeout => 9}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@identity => {"tags" => [@tag]}}).once
      @request.should_receive(:raw_response).and_return("raw response").once
      @manager.query_tags(@tags, :raw => true, :timeout => 9) { |r| @result = r }
      @result.should == "raw response"
    end

    it "yields error result and logs error" do
      @idempotent_request.should_receive(:new).with("/mapper/query_tags",
                                                    {:agent_identity => @identity, :tags => [@tag]},
                                                    {}).and_return(@request).once
      @log.should_receive(:error).with(/Failed to query tags/).once
      @request.should_receive(:errback).and_yield("error").once
      @request.should_receive(:callback).once
      @manager.query_tags(@tag) { |r| @result = r }
      @result.should == "error"
    end
  end

  context :query_tags_raw do

    before(:each) do
      @request.should_receive(:raw_response).and_return("raw response").once
    end

    it "always yields raw response" do
      @idempotent_request.should_receive(:new).with("/mapper/query_tags",
                                                    {:agent_identity => @identity, :tags => [@tag]},
                                                    {}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@identity => {"tags" => [@tag]}, @agent_id1 => {"tags" => [@tag]}}).once
      @manager.query_tags_raw(@tag) { |r| @result = r }
      @result.should == "raw response"
    end

    it "queries for agents having individual tag and always yields raw response" do
      @idempotent_request.should_receive(:new).with("/mapper/query_tags",
                                                    {:agent_identity => @identity, :tags => [@tag]},
                                                    {}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@identity => {"tags" => [@tag]}, @agent_id1 => {"tags" => [@tag]}}).once
      @manager.query_tags_raw(@tag) { |r| @result = r }
      @result.should == "raw response"
    end

    it "queries for agents having multiple tags always yields raw response" do
      @idempotent_request.should_receive(:new).with("/mapper/query_tags",
                                                    {:agent_identity => @identity, :tags => @tags},
                                                    {}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@agent_id1 => {"tags" => @tags}}).once
      @manager.query_tags_raw(@tags) { |r| @result = r }
      @result.should == "raw response"
    end

    it "queries for selected agents" do
      @idempotent_request.should_receive(:new).with("/mapper/query_tags",
                                                    {:agent_identity => @identity, :agent_ids => @agent_ids, :tags => @tags},
                                                    {}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@agent_id1 => {"tags" => @tags}}).once
      @manager.query_tags_raw(@tags, @agent_ids) { |r| @result = r }
      @result.should == "raw response"
    end

    it "forwards timeout option" do
      @idempotent_request.should_receive(:new).with("/mapper/query_tags",
                                                    {:agent_identity => @identity, :tags => @tags},
                                                    {:timeout => 9}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@identity => {"tags" => [@tag]}}).once
      @manager.query_tags_raw(@tags, nil, :timeout => 9) { |r| @result = r }
      @result.should == "raw response"
    end
  end

  context :add_tags do

    before(:each) do
      @request.should_receive(:raw_response).and_return("raw response").once
      @agent.should_receive(:tags).and_return([]).once.by_default
      @agent.should_receive(:tags=).once.by_default
    end

    it "adds individual tag to agent" do
      @idempotent_request.should_receive(:new).with("/mapper/update_tags",
                                                    {:new_tags => [@tag], :obsolete_tags => []}).and_return(@request).once
      @manager.add_tags(@tag).should be_true
    end

    it "adds multiple tags to agent" do
      @idempotent_request.should_receive(:new).with("/mapper/update_tags",
                                                    {:new_tags => @tags, :obsolete_tags => []}).and_return(@request).once
      @manager.add_tags(@tags).should be_true
    end

    it "optionally yields raw response" do
      @idempotent_request.should_receive(:new).with("/mapper/update_tags",
                                                    {:new_tags => @tags, :obsolete_tags => []}).and_return(@request).once
      @request.should_receive(:callback).and_yield("result").once
      @manager.add_tags(@tags) { |r| @result = r }
      @result.should == "raw response"
    end

    it "updates local tags" do
      @agent.should_receive(:tags).and_return([@tag1]).once
      @agent.should_receive(:tags=).should_receive([@tag]).once
      @idempotent_request.should_receive(:new).with("/mapper/update_tags",
                                                    {:new_tags => [@tag], :obsolete_tags => []}).and_return(@request).once
      @manager.add_tags(@tag).should be_true
    end
  end

  context :remove_tags do

    before(:each) do
      @request.should_receive(:raw_response).and_return("raw response").once
      @agent.should_receive(:tags).and_return([@tag]).once.by_default
      @agent.should_receive(:tags=).once.by_default
    end

    it "removes individual tag to agent" do
      @idempotent_request.should_receive(:new).with("/mapper/update_tags",
                                                    {:new_tags => [], :obsolete_tags => [@tag]}).and_return(@request).once
      @manager.remove_tags(@tag).should be_true
    end

    it "removes multiple tags to agent" do
      @idempotent_request.should_receive(:new).with("/mapper/update_tags",
                                                    {:new_tags => [], :obsolete_tags => @tags}).and_return(@request).once
      @manager.remove_tags(@tags).should be_true
    end

    it "optionally yields raw response" do
      @idempotent_request.should_receive(:new).with("/mapper/update_tags",
                                                    {:new_tags => [], :obsolete_tags => @tags}).and_return(@request).once
      @request.should_receive(:callback).and_yield("result").once
      @manager.remove_tags(@tags) { |r| @result = r }
      @result.should == "raw response"
    end

    it "updates local tags" do
      @agent.should_receive(:tags).and_return([]).once
      @agent.should_receive(:tags=).should_receive([@tag]).once
      @idempotent_request.should_receive(:new).with("/mapper/update_tags",
                                                    {:new_tags => [], :obsolete_tags => [@tag]}).and_return(@request).once
      @manager.remove_tags(@tag).should be_true
    end
  end

  context :update_tags do

    before(:each) do
      @agent.should_receive(:tags).and_return([]).once.by_default
    end

    it "checks that agent has been set" do
      @manager.agent = nil
      @agent.should_receive(:tags).never
      lambda { @manager.update_tags([@tag], [@tag1]) }.should raise_error(ArgumentError, "Must set agent= before using tag manager")
    end

    it "adds and removes tags for agent" do
      @idempotent_request.should_receive(:new).with("/mapper/update_tags",
                                                    {:new_tags => [@tag], :obsolete_tags => [@tag1]}).and_return(@request).once
      @agent.should_receive(:tags=).never
      @manager.update_tags([@tag], [@tag1]).should be_true
    end

    it "yields raw response if block given" do
      @idempotent_request.should_receive(:new).with("/mapper/update_tags",
                                                    {:new_tags => [@tag], :obsolete_tags => [@tag1]}).and_return(@request).once
      @request.should_receive(:raw_response).and_return("raw response").once
      @agent.should_receive(:tags=).once
      @manager.update_tags([@tag], [@tag1]) { |r| @result = r }
      @result.should == "raw response"
    end

    it "updates local tags if block given and successful" do
      @idempotent_request.should_receive(:new).with("/mapper/update_tags",
                                                    {:new_tags => [@tag], :obsolete_tags => [@tag1]}).and_return(@request).once
      @request.should_receive(:raw_response).and_return("raw response").once
      @agent.should_receive(:tags=).with([@tag]).once
      @manager.update_tags([@tag], [@tag1]) { |r| @result = r }
      @result.should == "raw response"
    end

    it "yields error result and does not update local tags" do
      @idempotent_request.should_receive(:new).with("/mapper/update_tags",
                                                    {:new_tags => [@tag], :obsolete_tags => [@tag1]}).and_return(@request).once
      @request.should_receive(:raw_response).and_return("error").once
      @request.should_receive(:errback).and_yield("error").once
      @request.should_receive(:callback).once
      @agent.should_receive(:tags=).never
      @manager.update_tags([@tag], [@tag1]) { |r| @result = r }
      @result.should == "error"
    end
  end

  context :clear do

    it "clears all agent tags" do
      @request.should_receive(:raw_response).and_return("raw response").once
      @agent.should_receive(:tags).and_return(@tags).twice
      @agent.should_receive(:tags=).with([]).once
      @idempotent_request.should_receive(:new).with("/mapper/update_tags",
                                                    {:new_tags => [], :obsolete_tags => @tags}).and_return(@request).once
      @manager.clear { |r| @result = r }
      @result.should == "raw response"
    end
  end
end
