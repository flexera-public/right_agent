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

    # Wait 5 seconds before retrying in case of failure
    DEFAULT_RETRY_DELAY = 5

    attr_reader :raw_response

    # Send idempotent request
    # Retry until timeout is reached (indefinitely if timeout <= 0)
    # Calls deferrable callback on completion, error callback on timeout
    #
    # === Parameters
    # operation(String):: Request operation (i.e. '/booter/get_boot_bundle')
    # payload(Hash):: Request payload
    # options[:retry_on_error](FalseClass|TrueClass):: Whether request should be retried
    #   if recipient returned an error
    # options[:timeout](Fixnum):: Number of seconds before error callback gets called
    # options[:retry_delay](Fixnum):: Number of seconds before retry, defaults to 5
    def initialize(operation, payload, options={})
      raise ArgumentError.new("options[:operation] is required") unless @operation = operation
      raise ArgumentError.new("options[:payload] is required") unless @payload = payload
      @retry_on_error = options[:retry_on_error] || false
      @timeout = options[:timeout] || -1
      @retry_delay = options[:retry_delay] || DEFAULT_RETRY_DELAY
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
          log_info(msg)
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
      res = OperationResult.non_delivery unless res
      if res.success?
        if @cancel_timer
          @cancel_timer.cancel
          @cancel_timer = nil
        end
        @done = true
        succeed(res.content)
      else
        if res.non_delivery?
          Log.info("Request non-delivery (#{res.content}) for #{@operation}")
        elsif res.retry?
          Log.info("RightScale not ready when trying to request #{@operation}")
        else
          Log.info("Request #{@operation} failed (#{res.content})")
        end
        if res.non_delivery? || res.retry? || @retry_on_error
          Log.info("Retrying in #{@retry_delay} seconds...")
          if @retry_delay > 0
            EM.add_timer(@retry_delay) { run }
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
