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
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'lib', 'right_agent', 'clients', 'event_mixin'))

describe RightScale::EventMixin do
  class Tester
    include RightScale::EventMixin
  end

  before(:each) do
    @tester = Tester.new
    @agent_id = "rs-agent-1-1"
    @agent_id2 = "rs-agent-2-2"
    @source = "rs-source-test-11"
    @version = RightScale::AgentConfig.protocol_version
  end

  context :event_trace do
    it "creates trace from event UUID" do
      event = {:uuid => "uuid", :source => @source, :version => @version}
      @tester.event_trace(event).should == "<uuid>"
    end

    it "adds event ID to trace for sequenced events" do
      event = {:uuid => "uuid", :id => 2, :source => @source, :version => @version}
      @tester.event_trace(event).should == "<uuid:2>"
    end

    it "creates trace for string event UUID" do
      @tester.event_trace("uuid").should == "<uuid>"
    end

    it "creates trace for numeric event ID" do
      @tester.event_trace(2).should == "<..:2>"
    end
  end

  context :event_text do
    it "creates event text" do
      event_data = {:result => "done", :duration => 10, :request_uuid => "uuid2", :request_from => @agent_id2}
      event = {:uuid => "uuid", :type => "Result", :source => @agent_id, :data => event_data, :version => @version}
      @tester.send(:event_text, event).should == "<uuid> Result from rs-agent-1-1"
    end

    it "includes path if available" do
      event = {:uuid => "uuid", :type => "Push", :path => "/foo/bar", :source => @agent_id2, :data => {"some" => "data"},
               :version => @version}
      @tester.send(:event_text, event).should == "<uuid> Push /foo/bar from rs-agent-2-2"
    end

    it "excludes type if unavailable" do
      event = {:uuid => "uuid", :source => @source, :version => @version}
      @tester.send(:event_text, event).should == "<uuid> from rs-source-test-11"
    end

    it "includes id if event sequenced" do
      event = {:uuid => "uuid", :id => 2, :source => @source, :version => @version}
      @tester.send(:event_text, event).should == "<uuid:2> from rs-source-test-11"
    end

    it "includes to if available" do
      event = {:uuid => "uuid", :type => "Push", :path => "/foo/bar", :source => @agent_id2, :to => @agent_id,
               :data => {"some" => "data"}, :version => @version}
      @tester.send(:event_text, event).should == "<uuid> Push /foo/bar from rs-agent-2-2 to rs-agent-1-1"
    end
  end
end
