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

describe RightScale::PendingRequest do

  context :initialize do
    it "creates pending request" do
      now = Time.now
      response_handler = lambda { |_| }
      pending_request = RightScale::PendingRequest.new(:send_request, now, response_handler)
      pending_request.kind.should == :send_request
      pending_request.receive_time.should == now
      pending_request.response_handler.should == response_handler
      pending_request.retry_parent_token.should be_nil
      pending_request.non_delivery.should be_nil
    end
  end

  context :retry_parent_token do
    it "can be set" do
      pending_request = RightScale::PendingRequest.new(:send_request, Time.now, lambda { |_| })
      pending_request.retry_parent_token = "retry token"
      pending_request.retry_parent_token.should == "retry token"
    end
  end

  context :non_delivery do
    it "can be set" do
      pending_request = RightScale::PendingRequest.new(:send_request, Time.now, lambda { |_| })
      pending_request.non_delivery = "because"
      pending_request.non_delivery.should == "because"
    end
  end
end

describe RightScale::PendingRequests do

  # Add specified kinds of pending requests to pending_requests hash
  def add_requests(pending_requests, kinds)
    i = 0
    kinds.each do |kind|
      i += 1
      pending_requests["token#{i}"] = RightScale::PendingRequest.new(kind, Time.now, lambda { |_| })
    end
  end

  before(:all) do
    @push = :send_push
    @request = :send_request
  end

  context :initialize do
    it "is a hash" do
      pending_requests = RightScale::PendingRequests.new
      pending_requests.should be_a(Hash)
      pending_requests.size.should == 0
    end
  end

  context :[]= do
    it "stores pending request" do
      pending_requests = RightScale::PendingRequests.new
      pending_request = RightScale::PendingRequest.new(:send_request, Time.now, lambda { |_| })
      pending_requests["token"] = pending_request
      pending_requests["token"].should == pending_request
    end

    it "deletes old pending send_push requests" do
      now = Time.now
      age = RightScale::PendingRequests::MAX_PUSH_AGE + 21
      flexmock(Time).should_receive(:now).and_return(now, now + 10, now + 10, now + 20, now + 20, now + age, now + age)
      pending_requests = RightScale::PendingRequests.new
      add_requests(pending_requests, [@request, @push, @push])
      pending_requests.size.should == 2
      pending_requests["token1"].should_not be_nil
      pending_requests["token2"].should be_nil
      pending_requests["token3"].should_not be_nil
      pending_requests.instance_variable_get(:@last_cleanup).should == now + age
    end
  end

  context :kind do
    it "returns pending requests of specified kind" do
      pending_requests = RightScale::PendingRequests.new
      add_requests(pending_requests, [@request, @push, @push])
      requests = pending_requests.kind(:send_request)
      requests.size.should == 1
      requests["token1"].should_not be_nil
      requests = pending_requests.kind(:send_push)
      requests.size.should == 2
      requests["token2"].should_not be_nil
      requests["token3"].should_not be_nil
    end
  end

  context :youngest_age do
    it "returns age of youngest pending request" do
      now = Time.now
      flexmock(Time).should_receive(:now).and_return(now, now + 10, now + 10, now + 20, now + 20, now + 30)
      pending_requests = RightScale::PendingRequests.new
      add_requests(pending_requests, [@request, @push])
      RightScale::PendingRequests.youngest_age(pending_requests).should == 10
    end
  end

  context :oldest_age do
    it "returns age of oldest pending request" do
      now = Time.now
      flexmock(Time).should_receive(:now).and_return(now, now + 10, now + 10, now + 20, now + 20, now + 30)
      pending_requests = RightScale::PendingRequests.new
      add_requests(pending_requests, [@request, @push])
      RightScale::PendingRequests.oldest_age(pending_requests).should == 20
    end
  end
end