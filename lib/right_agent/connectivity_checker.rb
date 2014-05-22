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

module RightScale

  # Broker connectivity checker
  # Checks connectivity when requested
  class ConnectivityChecker

    # Minimum number of seconds between restarts of the inactivity timer
    MIN_RESTART_INACTIVITY_TIMER_INTERVAL = 60

    # Number of seconds to wait for ping response from a RightNet router when checking connectivity
    PING_TIMEOUT = 30

    # Default maximum number of consecutive ping timeouts before attempt to reconnect
    MAX_PING_TIMEOUTS = 3

    # Timer while waiting for RightNet router ping response
    attr_accessor :ping_timer

    def initialize(sender, check_interval, ping_stats)
      @sender = sender
      @check_interval = check_interval
      @ping_timeouts = {}
      @ping_timer = nil
      @ping_stats = ping_stats
      @last_received = Time.now
      @message_received_callbacks = []
      restart_inactivity_timer if @check_interval > 0
    end

    # Update the time this agent last received a request or response message
    # and restart the inactivity timer thus deferring the next connectivity check
    # Also forward this message receipt notification to any callbacks that have registered
    #
    # === Block
    # Optional block without parameters that is activated when a message is received
    #
    # === Return
    # true:: Always return true
    def message_received(&callback)
      if block_given?
        @message_received_callbacks << callback
      else
        @message_received_callbacks.each { |c| c.call }
        if @check_interval > 0
          now = Time.now
          if (now - @last_received) > MIN_RESTART_INACTIVITY_TIMER_INTERVAL
            @last_received = now
            restart_inactivity_timer
          end
        end
      end
      true
    end

    # Check whether broker connection is usable by pinging a router via that broker
    # Attempt to reconnect if ping does not respond in PING_TIMEOUT seconds and
    # if have reached timeout limit
    # Ignore request if already checking a connection
    #
    # === Parameters
    # id(String):: Identity of specific broker to use to send ping, defaults to any
    #   currently connected broker
    # max_ping_timeouts(Integer):: Maximum number of ping timeouts before attempt
    #   to reconnect, defaults to MAX_PING_TIMEOUTS
    #
    # === Return
    # true:: Always return true
    def check(id = nil, max_ping_timeouts = MAX_PING_TIMEOUTS)
      unless @terminating || @ping_timer || (id && !@sender.agent.client.connected?(id))
        @ping_id = id
        @ping_timer = EM::Timer.new(PING_TIMEOUT) do
          if @ping_id
            begin
              @ping_stats.update("timeout")
              @ping_timer = nil
              @ping_timeouts[@ping_id] = (@ping_timeouts[@ping_id] || 0) + 1
              if @ping_timeouts[@ping_id] >= max_ping_timeouts
                ErrorTracker.log(self, "Mapper ping via broker #{@ping_id} timed out after #{PING_TIMEOUT} seconds and now " +
                                       "reached maximum of #{max_ping_timeouts} timeout#{max_ping_timeouts > 1 ? 's' : ''}, " +
                                       "attempting to reconnect")
                host, port, index, priority = @sender.client.identity_parts(@ping_id)
                @sender.agent.connect(host, port, index, priority, force = true)
              else
                Log.warning("Mapper ping via broker #{@ping_id} timed out after #{PING_TIMEOUT} seconds")
              end
            rescue Exception => e
              ErrorTracker.log(self, "Failed to reconnect to broker #{@ping_id}", e)
            end
          else
            @ping_timer = nil
          end
        end

        handler = lambda do |_|
          begin
            if @ping_timer
              @ping_stats.update("success")
              @ping_timer.cancel
              @ping_timer = nil
              @ping_timeouts[@ping_id] = 0
              @ping_id = nil
            end
          rescue Exception => e
            ErrorTracker.log(self, "Failed to cancel router ping", e)
          end
        end
        request = Request.new("/router/ping", nil, {:from => @sender.identity, :token => AgentIdentity.generate})
        @sender.pending_requests[request.token] = PendingRequest.new(Request, Time.now, handler)
        ids = [@ping_id] if @ping_id
        @ping_id = @sender.send(:publish, request, ids).first
      end
      true
    end

    # Prepare for agent termination
    #
    # === Return
    # true:: Always return true
    def terminate
      @terminating = true
      @check_interval = 0
      if @ping_timer
        @ping_timer.cancel
        @ping_timer = nil
      end
      if @inactivity_timer
        @inactivity_timer.cancel
        @inactivity_timer = nil
      end
      true
    end

    protected

    # Start timer that waits for inactive messaging period to end before checking connectivity
    #
    # === Return
    # true:: Always return true
    def restart_inactivity_timer
      @inactivity_timer.cancel if @inactivity_timer
      @inactivity_timer = EM::Timer.new(@check_interval) do
        begin
          check(id = nil, max_ping_timeouts = 1)
        rescue Exception => e
          ErrorTracker.log(self, "Failed connectivity check", e)
        end
      end
      true
    end

  end # ConnectivityChecker

end # RightScale
