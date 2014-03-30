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

  # Handler for queueing of requests when offline relative to RightNet
  # and then sending the requests when successfully reconnect
  class OfflineHandler

    # Maximum seconds to wait before starting flushing offline queue when disabling offline mode
    MAX_QUEUE_FLUSH_DELAY = 2 * 60

    # Maximum number of offline queued requests before triggering restart vote
    MAX_QUEUED_REQUESTS = 100

    # Number of seconds that should be spent in offline mode before triggering a restart vote
    RESTART_VOTE_DELAY = 15 * 60

    # (Symbol) Current queue state with possible values:
    #   Value          Description                Action               Next state
    #   :created       Queue created              init                 :initializing
    #   :initializing  Agent still initializing   start                :running
    #   :running       Queue has been started     disable when offline :flushing
    #   :flushing      Sending queued requests    enable               :running
    #   :terminating   Agent terminating
    attr_reader :state

    # (Symbol) Current offline handling mode with possible values:
    #   Value          Description
    #   :initializing  Agent still initializing
    #   :online        Agent connected
    #   :offline       Agent disconnected
    attr_reader :mode

    # (Array) Offline queue
    attr_accessor :queue

    # Create offline queueing handler
    #
    # === Parameters
    # restart_callback(Proc):: Callback that is activated on each restart vote with votes being initiated
    #   by offline queue exceeding MAX_QUEUED_REQUESTS
    # offline_stats(RightSupport::Stats::Activity):: Offline queue tracking statistics
    def initialize(restart_callback, offline_stats)
      @restart_vote = restart_callback
      @restart_vote_timer = nil
      @restart_vote_count = 0
      @offline_stats = offline_stats
      @state = :created
      @mode = :initializing
      @queue = []
    end

    # Initialize the offline queue
    # All requests sent prior to running this initialization are queued
    # and then are sent once this initialization has run
    # All requests following this call and prior to calling start
    # are prepended to the request queue
    #
    # === Return
    # true:: Always return true
    def init
      @state = :initializing if @state == :created
      true
    end

    # Switch to online mode and send all buffered messages
    #
    # === Return
    # true:: Always return true
    def start
      if @state == :initializing
        if @mode == :offline
          @state = :running
        else
          @state = :flushing
          flush
        end
        @mode = :online if @mode == :initializing
      end
      true
    end

    # Is agent currently offline?
    #
    # === Return
    # (Boolean):: true if agent offline, otherwise false
    def offline?
      @mode == :offline || @state == :created
    end

    # In request queueing mode?
    #
    # === Return
    # (Boolean):: true if should queue request, otherwise false
    def queueing?
      offline? && @state != :flushing
    end

    # Switch to offline mode
    # In this mode requests are queued in memory rather than being sent
    # Idempotent
    #
    # === Return
    # true:: Always return true
    def enable
      if offline?
        if @state == :flushing
          # If we were in offline mode then switched back to online but are still in the
          # process of flushing the in-memory queue and are now switching to offline mode
          # again then stop the flushing
          @state = :running
        end
      else
        Log.info("[offline] Disconnect from RightNet detected, entering offline mode")
        Log.info("[offline] Messages will be queued in memory until RightNet connection is re-established")
        @offline_stats.update
        @queue ||= []  # Ensure queue is valid without losing any messages when going offline
        @mode = :offline
        start_timer
      end
      true
    end

    # Switch back to sending requests after in-memory queue gets flushed
    # Idempotent
    #
    # === Return
    # true:: Always return true
    def disable
      if offline? && @state != :created
        Log.info("[offline] Connection to RightNet re-established")
        @offline_stats.finish
        cancel_timer
        @state = :flushing
        # Wait a bit to avoid flooding RightNet
        EM.add_timer(rand(MAX_QUEUE_FLUSH_DELAY)) { flush }
      end
      true
    end

    # Queue given request in memory
    #
    # === Parameters
    # request(Hash):: Request to be stored
    #
    # === Return
    # true:: Always return true
    def queue_request(kind, type, payload, target, callback)
      request = {:kind => kind, :type => type, :payload => payload, :target => target, :callback => callback}
      Log.info("[offline] Queuing request: #{request.inspect}")
      vote_to_restart if (@restart_vote_count += 1) >= MAX_QUEUED_REQUESTS
      if @state == :initializing
        # We are in the initialization callback, requests should be put at the head of the queue
        @queue.unshift(request)
      else
        @queue << request
      end
      true
    end

    # Prepare for agent termination
    #
    # === Return
    # true:: Always return true
    def terminate
      @state = :terminating
      cancel_timer
      true
    end

    protected

    # Send any requests that were queued while in offline mode
    # Do this asynchronously to allow for agents to respond to requests
    # Once all in-memory requests have been flushed, switch off offline mode
    #
    # === Parameters
    # again(Boolean):: Whether being called in a loop
    #
    # === Return
    # true:: Always return true
    def flush(again = false)
      if @state == :flushing
        Log.info("[offline] Starting to flush request queue of size #{@queue.size}") unless again || @mode == :initializing
        if @queue.any?
          r = @queue.shift
          if r[:callback]
            Sender.instance.send(r[:kind], r[:type], r[:payload], r[:target]) { |result| r[:callback].call(result) }
          else
            Sender.instance.send(r[:kind], r[:type], r[:payload], r[:target])
          end
        end
        if @queue.empty?
          Log.info("[offline] Request queue flushed, resuming normal operations") unless @mode == :initializing
          @mode = :online
          @state = :running
        else
          EM.next_tick { flush(true) }
        end
      end
      true
    end

    # Vote for restart and reset trigger
    #
    # === Parameters
    # timer_trigger(Boolean):: true if vote was triggered by timer, false if it
    #   was triggered by number of messages in in-memory queue
    #
    # === Return
    # true:: Always return true
    def vote_to_restart(timer_trigger = false)
      if @restart_vote
        @restart_vote.call
        if timer_trigger
          start_timer
        else
          @restart_vote_count = 0
        end
      end
      true
    end

    # Start restart vote timer
    #
    # === Return
    # true:: Always return true
    def start_timer
      if @restart_vote && @state != :terminating
        @restart_vote_timer ||= EM::Timer.new(RESTART_VOTE_DELAY) { vote_to_restart(timer_trigger = true) }
      end
      true
    end

    # Cancel restart vote timer
    #
    # === Return
    # true:: Always return true
    def cancel_timer
      if @restart_vote_timer
        @restart_vote_timer.cancel
        @restart_vote_timer = nil
        @restart_vote_count = 0
      end
      true
    end

  end # OfflineHandler

end # RightScale
