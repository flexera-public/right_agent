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
    @identity = "rs-agent-1-1"
    @agent_href = "/api/clouds/1/instances/1"
    @agent_href2 = "/api/clouds/2/instances/2"
    @agent = flexmock("agent", :self_href => @agent_href, :identity => @identity)
    @hrefs = [@agent_href, @agent_href2]
    @manager = RightScale::AgentTagManager.instance
    @manager.agent = @agent
    @request = flexmock("request", :run => true)
    @request.should_receive(:callback).and_yield("result").by_default
    @request.should_receive(:errback).by_default
    @request.should_receive(:raw_response).and_return("raw response").by_default
    @retryable_request = flexmock(RightScale::RetryableRequest)
    @tag = "some:tag=value"
    @tag1 = "other:tag=value"
    @tags = [@tag, @tag1]
    @result = nil
  end

  context :tags do

    before(:each) do
      @retryable_request.should_receive(:new).with("/router/query_tags",
          {:agent_identity => @identity, :hrefs => [@agent_href]}, {}).and_return(@request).once.by_default
    end

    it "retrieves current agent tags" do
      @request.should_receive(:callback).and_yield({@agent_href => {"tags" => [@tag]}}).once
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
      @retryable_request.should_receive(:new).with("/router/query_tags",
          {:agent_identity => @identity, :hrefs => [@agent_href]}, {:timeout => 9}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@agent_href => {"tags" => [@tag]}}).once
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
      @retryable_request.should_receive(:new).with("/router/query_tags",
          {:agent_identity => @identity, :tags => [@tag]}, {}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@identity => {"tags" => [@tag]}, @agent_href => {"tags" => [@tag]}}).once
      @manager.query_tags(@tag) { |r| @result = r }
      @result.should == {@identity => {"tags" => [@tag]}, @agent_href => {"tags" => [@tag]}}
    end

    it "queries for agents having multiple tags" do
      @retryable_request.should_receive(:new).with("/router/query_tags",
          {:agent_identity => @identity, :tags => @tags}, {}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@agent_href => {"tags" => @tags}}).once
      @manager.query_tags(@tags) { |r| @result = r }
      @result.should == {@agent_href => {"tags" => @tags}}
    end

    it "forwards options" do
      @retryable_request.should_receive(:new).with("/router/query_tags",
          {:agent_identity => @identity, :tags => @tags}, {:timeout => 9}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@identity => {"tags" => [@tag]}}).once
      @request.should_receive(:raw_response).and_return("raw response").once
      @manager.query_tags(@tags, :raw => true, :timeout => 9) { |r| @result = r }
      @result.should == "raw response"
    end

    it "yields error result and logs error" do
      @retryable_request.should_receive(:new).with("/router/query_tags",
          {:agent_identity => @identity, :tags => [@tag]}, {}).and_return(@request).once
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
      @retryable_request.should_receive(:new).with("/router/query_tags",
          {:agent_identity => @identity, :tags => [@tag]}, {}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@identity => {"tags" => [@tag]}, @agent_href => {"tags" => [@tag]}}).once
      @manager.query_tags_raw(@tag) { |r| @result = r }
      @result.should == "raw response"
    end

    it "queries for agents having individual tag and always yields raw response" do
      @retryable_request.should_receive(:new).with("/router/query_tags",
          {:agent_identity => @identity, :tags => [@tag]}, {}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@identity => {"tags" => [@tag]}, @agent_href => {"tags" => [@tag]}}).once
      @manager.query_tags_raw(@tag) { |r| @result = r }
      @result.should == "raw response"
    end

    it "queries for agents having multiple tags always yields raw response" do
      @retryable_request.should_receive(:new).with("/router/query_tags",
          {:agent_identity => @identity, :tags => @tags}, {}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@agent_href => {"tags" => @tags}}).once
      @manager.query_tags_raw(@tags) { |r| @result = r }
      @result.should == "raw response"
    end

    it "queries for selected agents" do
      @retryable_request.should_receive(:new).with("/router/query_tags",
          {:agent_identity => @identity, :hrefs => @hrefs, :tags => @tags}, {}).and_return(@request).once
      @request.should_receive(:callback).and_yield({@agent_href => {"tags" => @tags}}).once
      @manager.query_tags_raw(@tags, @hrefs) { |r| @result = r }
      @result.should == "raw response"
    end

    it "forwards timeout option" do
      @retryable_request.should_receive(:new).with("/router/query_tags",
          {:agent_identity => @identity, :tags => @tags}, {:timeout => 9}).and_return(@request).once
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
      @retryable_request.should_receive(:new).with("/router/add_tags", {:tags => [@tag]}).and_return(@request).once
      @manager.add_tags(@tag).should be_true
    end

    it "adds multiple tags to agent" do
      @retryable_request.should_receive(:new).with("/router/add_tags", {:tags => @tags}).and_return(@request).once
      @manager.add_tags(@tags).should be_true
    end

    it "optionally yields raw response" do
      @retryable_request.should_receive(:new).with("/router/add_tags", {:tags => @tags}).and_return(@request).once
      @request.should_receive(:callback).and_yield("result").once
      @manager.add_tags(@tags) { |r| @result = r }
      @result.should == "raw response"
    end

    it "updates local tags" do
      @agent.should_receive(:tags).and_return([@tag1]).once
      @agent.should_receive(:tags=).should_receive([@tag]).once
      @retryable_request.should_receive(:new).with("/router/add_tags", {:tags => [@tag]}).and_return(@request).once
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
      @retryable_request.should_receive(:new).with("/router/delete_tags", {:tags => [@tag]}).and_return(@request).once
      @manager.remove_tags(@tag).should be_true
    end

    it "removes multiple tags to agent" do
      @retryable_request.should_receive(:new).with("/router/delete_tags", {:tags => @tags}).and_return(@request).once
      @manager.remove_tags(@tags).should be_true
    end

    it "optionally yields raw response" do
      @retryable_request.should_receive(:new).with("/router/delete_tags", {:tags => @tags}).and_return(@request).once
      @request.should_receive(:callback).and_yield("result").once
      @manager.remove_tags(@tags) { |r| @result = r }
      @result.should == "raw response"
    end

    it "updates local tags" do
      @agent.should_receive(:tags).and_return([]).once
      @agent.should_receive(:tags=).should_receive([@tag]).once
      @retryable_request.should_receive(:new).with("/router/delete_tags", {:tags => [@tag]}).and_return(@request).once
      @manager.remove_tags(@tag).should be_true
    end
  end

  context :do_update do

    before(:each) do
      @agent.should_receive(:tags).and_return([]).once.by_default
    end

    it "checks that agent has been set" do
      @manager.agent = nil
      @agent.should_receive(:tags).never
      lambda { @manager.send(:do_update, [@tag], []) }.should \
          raise_error(ArgumentError, "Must set agent= before using tag manager")
    end

    it "does not allow both add and removal of tags in same request" do
      @agent.should_receive(:tags).never
      lambda { @manager.send(:do_update, [@tag], [@tag1]) }.should \
          raise_error(ArgumentError, "Cannot add and remove tags in same update")
    end

    it "adds tags for agent" do
      @retryable_request.should_receive(:new).with("/router/add_tags", {:tags => [@tag]}).and_return(@request).once
      @agent.should_receive(:tags=).never
      @manager.send(:do_update, [@tag], []).should be_true
    end

    it "removes tags for agent" do
      @retryable_request.should_receive(:new).with("/router/delete_tags", {:tags => [@tag1]}).and_return(@request).once
      @agent.should_receive(:tags=).never
      @manager.send(:do_update, [], [@tag1]).should be_true
    end

    it "yields raw response if block given" do
      @retryable_request.should_receive(:new).with("/router/add_tags", {:tags => [@tag]}).and_return(@request).once
      @request.should_receive(:raw_response).and_return("raw response").once
      @agent.should_receive(:tags=).once
      @manager.send(:do_update, [@tag], []) { |r| @result = r }
      @result.should == "raw response"
    end

    it "updates local tags if block given and successful" do
      @retryable_request.should_receive(:new).with("/router/add_tags", {:tags => [@tag]}).and_return(@request).once
      @request.should_receive(:raw_response).and_return("raw response").once
      @agent.should_receive(:tags=).with([@tag]).once
      @manager.send(:do_update, [@tag], []) { |r| @result = r }
      @result.should == "raw response"
    end

    it "yields error result and does not update local tags" do
      @retryable_request.should_receive(:new).with("/router/add_tags", {:tags => [@tag]}).and_return(@request).once
      @request.should_receive(:raw_response).and_return("error").once
      @request.should_receive(:errback).and_yield("error").once
      @request.should_receive(:callback).once
      @agent.should_receive(:tags=).never
      @manager.send(:do_update, [@tag], []) { |r| @result = r }
      @result.should == "error"
    end
  end

  context :clear do

    it "clears all agent tags" do
      @request.should_receive(:raw_response).and_return("raw response").once
      @agent.should_receive(:tags).and_return(@tags).twice
      @agent.should_receive(:tags=).with([]).once
      @retryable_request.should_receive(:new).with("/router/delete_tags", {:tags => @tags}).and_return(@request).once
      @manager.clear { |r| @result = r }
      @result.should == "raw response"
    end
  end
end
