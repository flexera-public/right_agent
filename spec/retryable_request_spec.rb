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

require File.join(File.dirname(__FILE__), 'spec_helper')

describe RightScale::RetryableRequest do

  module RightScale
    class SenderMock
      include RightSupport::Ruby::EasySingleton
    end
  end

  before(:all) do
    if @sender_exists = RightScale.const_defined?(:Sender)
      RightScale.module_eval('OldSender = Sender')
    end
    RightScale.module_eval('Sender = SenderMock')
  end

  after(:all) do
    if @sender_exists
      RightScale.module_eval('Sender = OldSender')
    end
  end

  context ':targets option' do

    context 'when :targets => nil' do
      it 'should send target-less requests' do
        request = RightScale::RetryableRequest.new('type', 'payload')
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).
            and_yield(RightScale::OperationResult.non_delivery('test')).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_RETRY_DELAY, Proc).once
        request.run
      end
    end

    context 'when one target is specified' do
      it 'should send a targeted request' do
        request = RightScale::RetryableRequest.new('type', 'payload', :targets => ["rs-agent-1-1"])
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', {:agent_id => "rs-agent-1-1"}, Proc).
            and_yield(RightScale::OperationResult.non_delivery('test')).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_RETRY_DELAY, Proc).once
        request.run
      end
    end

    context 'when many targets are specified' do
      it 'should choose a random target' do
        request = RightScale::RetryableRequest.new('type', 'payload', :targets => ["rs-agent-1-1", "rs-agent-2-2", "rs-agent-3-3"])
        flexmock(RightScale::Sender.instance).should_receive(:send_request).and_return do |type, payload, target, block|
          type.should == 'type'
          payload.should == 'payload'
          ["rs-agent-1-1", "rs-agent-2-2", "rs-agent-3-3"].should include(target[:agent_id])
          block.call(RightScale::OperationResult.non_delivery('test'))
        end
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_RETRY_DELAY, Proc).once
        request.run
      end
    end

  end

  context ':retry_on_error option' do

    context 'when not specified' do
      it 'should fail if receives error response' do
        request = RightScale::RetryableRequest.new('type', 'payload')
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).
            and_yield(RightScale::OperationResult.error('test')).once
        flexmock(request).should_receive(:fail).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        request.run
      end
    end
    
    context 'when specified as true' do
      it 'should retry if receives error response' do
        request = RightScale::RetryableRequest.new('type', 'payload', :retry_on_error => true)
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).
            and_yield(RightScale::OperationResult.error('test')).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_RETRY_DELAY, Proc).once
        request.run
      end

      it 'should ignore duplicate responses' do
        request = RightScale::RetryableRequest.new('type', 'payload', :retry_on_error => true)
        flexmock(RightScale::Sender.instance).should_receive(:send_request).and_return do |t, p, tgt, b|
          5.times { b.call(RightScale::OperationResult.success('test')) }
        end
        flexmock(request).should_receive(:fail).never
        flexmock(request).should_receive(:succeed).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_RETRY_DELAY, Proc).never
        request.run
      end

      it 'should never retry after cancel response' do
        request = RightScale::RetryableRequest.new('type', 'payload', :retry_on_error => true)
        flexmock(RightScale::Log).should_receive(:info).with("Request type canceled (enough already)").once
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).
            and_yield(RightScale::OperationResult.cancel('enough already')).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_RETRY_DELAY, Proc).never
        request.run
      end
    end

  end

  context ':retry_delay options' do

    context 'when using default settings' do
      it 'should retry non-delivery responses' do
        request = RightScale::RetryableRequest.new('type', 'payload')
        flexmock(RightScale::Log).should_receive(:info).with(/Retrying in 5 seconds/).once
        flexmock(RightScale::Log).should_receive(:info).with("Request non-delivery (test) for type").once
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).
            and_yield(RightScale::OperationResult.non_delivery('test')).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_RETRY_DELAY, Proc).once
        request.run
      end

      it 'should retry retry responses' do
        request = RightScale::RetryableRequest.new('type', 'payload')
        flexmock(RightScale::Log).should_receive(:info).with(/Retrying in 5 seconds/).once
        flexmock(RightScale::Log).should_receive(:info).with("Request type failed (test) and should be retried").once
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).
            and_yield(RightScale::OperationResult.retry('test')).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_RETRY_DELAY, Proc).once
        request.run
      end

      it 'should log default retry reason if none given' do
        request = RightScale::RetryableRequest.new('type', 'payload')
        flexmock(RightScale::Log).should_receive(:info).with(/Retrying in 5 seconds/).once
        flexmock(RightScale::Log).should_receive(:info).with("Request type failed (RightScale not ready) and should be retried").once
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).
            and_yield(RightScale::OperationResult.retry).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_RETRY_DELAY, Proc).once
        request.run
      end

      it 'should ignore responses that arrive post-cancel' do
        request = RightScale::RetryableRequest.new('type', 'payload')
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).
            and_yield(RightScale::OperationResult.success('test')).once
        flexmock(request).should_receive(:fail).once
        flexmock(request).should_receive(:succeed).never
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_RETRY_DELAY, Proc).never
        request.cancel('test')
        request.run
      end

      it 'should never retry after cancel response' do
        request = RightScale::RetryableRequest.new('type', 'payload')
        flexmock(RightScale::Log).should_receive(:info).with("Request type canceled (enough already)").once
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).
            and_yield(RightScale::OperationResult.cancel('enough already')).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_RETRY_DELAY, Proc).never
        request.run
      end
    end

    context 'when a :retry_delay is specified' do
      it 'should control the initial retry delay' do
        retry_delay = 10
        request = RightScale::RetryableRequest.new('type', 'payload', :retry_delay => retry_delay)
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).
            and_yield(RightScale::OperationResult.retry('test')).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(retry_delay, Proc).once
        flexmock(EM).should_receive(:next_tick).never
        request.run
      end

      it 'should treat -1 as meaning no delay' do
        retry_delay = -1
        request = RightScale::RetryableRequest.new('type', 'payload', :retry_delay => retry_delay)
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).
            and_yield(RightScale::OperationResult.retry('test')).once
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(retry_delay, Proc).never
        flexmock(EM).should_receive(:next_tick).once
        request.run
      end
    end

    context 'when a :retry_delay_count is specified' do
      it 'should limit the number of retries using the :retry_delay value' do
        retry_delay = 10
        retry_delay_count = 1
        backoff_factor = RightScale::RetryableRequest::RETRY_BACKOFF_FACTOR
        request = RightScale::RetryableRequest.new('type', 'payload', :retry_delay => retry_delay,
                                                    :retry_delay_count => retry_delay_count)
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).
            and_yield(RightScale::OperationResult.retry('test')).twice
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(retry_delay, Proc).and_yield.once
        flexmock(EM).should_receive(:add_timer).with(retry_delay * backoff_factor, Proc).once
        flexmock(EM).should_receive(:next_tick).never
        request.run
      end

      it 'should backoff as delay time increases' do
        retry_delay = 10
        retry_delay_count = 2
        max_retry_delay = 30
        backoff_factor = RightScale::RetryableRequest::RETRY_BACKOFF_FACTOR
        request = RightScale::RetryableRequest.new('type', 'payload', :retry_delay => retry_delay,
                                                    :retry_delay_count => retry_delay_count,
                                                    :max_retry_delay => max_retry_delay)
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).
            and_yield(RightScale::OperationResult.retry('test')).times(4)
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(retry_delay, Proc).and_yield.twice
        flexmock(EM).should_receive(:add_timer).with(retry_delay * backoff_factor, Proc).and_yield.once
        flexmock(EM).should_receive(:add_timer).with(max_retry_delay, Proc).once
        flexmock(EM).should_receive(:next_tick).never
        request.run
        request.instance_variable_get(:@retry_delay_count).should == retry_delay_count / 2
      end
    end

    context 'when a :max_retry_delay is specified' do
      it 'should limit the retry delay total backoff' do
        retry_delay = 10
        retry_delay_count = 1
        max_retry_delay = 30
        backoff_factor = RightScale::RetryableRequest::RETRY_BACKOFF_FACTOR
        request = RightScale::RetryableRequest.new('type', 'payload', :retry_delay => retry_delay,
                                                    :retry_delay_count => retry_delay_count,
                                                    :max_retry_delay => max_retry_delay)
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).
            and_yield(RightScale::OperationResult.retry('test')).times(3)
        flexmock(EM).should_receive(:add_timer).with(RightScale::RetryableRequest::DEFAULT_TIMEOUT, Proc).once
        flexmock(EM).should_receive(:add_timer).with(retry_delay, Proc).and_yield.once
        flexmock(EM).should_receive(:add_timer).with(retry_delay * backoff_factor, Proc).and_yield.once
        flexmock(EM).should_receive(:add_timer).with(max_retry_delay, Proc).once
        flexmock(EM).should_receive(:next_tick).never
        request.run
      end
    end

  end

  context ':timeout option' do
    context 'when disable timeout' do
      it 'should not timeout' do
        request = RightScale::RetryableRequest.new('type', 'payload', :timeout => -1)
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).once
        flexmock(EM).should_receive(:add_timer).never
        request.run
      end
    end

    context 'when a timeout is specified' do
      it 'should time the response' do
        timeout = 10
        request = RightScale::RetryableRequest.new('type', 'payload', :timeout => timeout)
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).once
        flexmock(EM).should_receive(:add_timer).with(timeout, Proc).once
        request.run
      end

      it 'should log a message when timeout' do
        timeout = 10
        request = RightScale::RetryableRequest.new('type', 'payload', :timeout => timeout)
        flexmock(RightScale::Log).should_receive(:info).with("Request type timed out after 10 seconds").once
        flexmock(RightScale::Sender.instance).should_receive(:send_request).with('type', 'payload', nil, Proc).once
        flexmock(EM).should_receive(:add_timer).with(timeout, Proc).and_yield.once
        request.run
      end
    end
  end

end
