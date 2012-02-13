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

module RightScale

  class IdempotentRequest

    include OperationResultHelper
    include EM::Deferrable

    # Default delay before initial retry in case of failure with -1 meaning no delay
    DEFAULT_RETRY_DELAY = 5

    # Default minimum number of retries before beginning backoff
    DEFAULT_RETRY_DELAY_COUNT = 60

    # Maximum default delay before retry when backing off
    DEFAULT_MAX_RETRY_DELAY = 60

    # Factor used for exponential backoff of retry delay
    RETRY_BACKOFF_FACTOR = 2

    # Default timeout with -1 meaning never timeout
    DEFAULT_TIMEOUT = -1

    attr_reader :raw_response

    # Send idempotent request
    # Retry until timeout is reached (indefinitely if timeout <= 0)
    # Calls deferrable callback on completion, error callback on timeout
    #
    # === Parameters
    # operation(String):: Request operation (e.g., '/booter/get_boot_bundle')
    # payload(Hash):: Request payload
    # options(Hash):: Request options
    #   :targets(Array):: Targets from which to randomly choose one
    #   :retry_on_error(Boolean):: Whether request should be retried if recipient returned an error
    #   :retry_delay(Fixnum):: Number of seconds delay before initial retry with -1 meaning no delay,
    #     defaults to DEFAULT_RETRY_DELAY
    #   :retry_delay_count(Fixnum):: Minimum number of retries at initial :retry_delay value before
    #     increasing delay exponentially and decreasing this count exponentially, defaults to
    #     DEFAULT_RETRY_DELAY_COUNT
    #   :max_retry_delay(Fixnum):: Maximum number of seconds of retry delay, defaults to DEFAULT_MAX_RETRY_DELAY
    #   :timeout(Fixnum):: Number of seconds with no response before error callback gets called with
    #     -1 meaning never, defaults to DEFAULT_TIMEOUT
    #
    # === Raises
    # ArgumentError:: If operation or payload not specified
    def initialize(operation, payload, options = {})
      raise ArgumentError.new("operation is required") unless @operation = operation
      raise ArgumentError.new("payload is required") unless @payload = payload
      @retry_on_error = options[:retry_on_error] || false
      @timeout = options[:timeout] || DEFAULT_TIMEOUT
      @retry_delay = options[:retry_delay] || DEFAULT_RETRY_DELAY
      @retry_delay_count = options[:retry_delay_count] || DEFAULT_RETRY_DELAY_COUNT
      @max_retry_delay = options[:max_retry_delay] || DEFAULT_MAX_RETRY_DELAY
      @retries = 0
      @targets = options[:targets]
      @raw_response = nil
      @done = false
    end

    # Send request and retry until timeout is reached or response is received
    # Ignore duplicate responses
    # 
    # === Return
    # true:: Always return true
    def run
      Sender.instance.send_retryable_request(@operation, @payload, retrieve_target(@targets)) { |r| handle_response(r) }
      if @cancel_timer.nil? && @timeout > 0
        @cancel_timer = EM::Timer.new(@timeout) do
          msg = "Request #{@operation} timed out after #{@timeout} seconds"
          Log.info(msg)
          cancel(msg)
        end
      end
      true
    end
    
    # Cancel request and call error callback
    #
    # === Parameters
    # msg(String):: Reason why request is cancelled, given to error callback
    # 
    # === Return
    # true:: Always return true
    def cancel(msg)
      if @cancel_timer
        @cancel_timer.cancel
        @cancel_timer = nil
      end
      @done = true
      fail(msg)
      true
    end

    protected

    # Process request response and retry if needed
    #
    # === Parameters
    # r(Result):: Request result
    #
    # === Return
    # true:: Always return true
    def handle_response(r)
      return true if @done
      @raw_response = r
      res = result_from(r)
      if res.success?
        if @cancel_timer
          @cancel_timer.cancel
          @cancel_timer = nil
        end
        @done = true
        succeed(res.content)
      else
        reason = res.content
        if res.non_delivery?
          Log.info("Request non-delivery (#{reason}) for #{@operation}")
        elsif res.retry?
          reason = (reason && !reason.empty?) ? reason : "RightScale not ready"
          Log.info("Request #{@operation} failed (#{reason}) and should be retried")
        elsif res.cancel?
          reason = (reason && !reason.empty?) ? reason : "RightScale cannot execute request"
          Log.info("Request #{@operation} canceled (#{reason})")
        else
          Log.info("Request #{@operation} failed (#{reason})")
        end
        if (res.non_delivery? || res.retry? || @retry_on_error) && !res.cancel?
          Log.info("Retrying in #{@retry_delay} seconds...")
          if @retry_delay > 0
            this_delay = @retry_delay
            if (@retries += 1) >= @retry_delay_count
              @retry_delay = [@retry_delay * RETRY_BACKOFF_FACTOR, @max_retry_delay].min
              @retry_delay_count = [@retry_delay_count / RETRY_BACKOFF_FACTOR, 1].max
              @retries = 0
            end
            EM.add_timer(this_delay) { run }
          else
            EM.next_tick { run }
          end
        else
          cancel(res.content)
        end
      end
      true
    end
    
    def retrieve_target(targets)
      targets[rand(0xffff) % targets.size] if targets
    end

  end # IdempotentRequest

end # RightScale
