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

  # Request that is waiting for a response
  class PendingRequest

    # (Symbol) Kind of request: :send_push or :send_request
    attr_reader :kind

    # (Time) Time when request message was received
    attr_reader :receive_time

    # (Proc) Block to be activated when response is received
    attr_reader :response_handler

    # (String) Token for parent request in a retry situation
    attr_accessor :retry_parent_token

    # (String) Non-delivery reason if any
    attr_accessor :non_delivery

    def initialize(kind, receive_time, response_handler)
      @kind = kind
      @receive_time = receive_time
      @response_handler = response_handler
      @retry_parent_token = nil
      @non_delivery = nil
    end

  end # PendingRequest

  # Cache for requests that are waiting for a response
  # Automatically deletes push requests when get too old
  # Retains non-push requests until explicitly deleted
  class PendingRequests < Hash

    # Maximum number of seconds to retain send pushes in cache
    MAX_PUSH_AGE = 2 * 60

    # Minimum number of seconds between push cleanups
    MIN_CLEANUP_INTERVAL = 15

    # Create cache
    def initialize
      @last_cleanup = Time.now
      super
    end

    # Store pending request
    #
    # === Parameters
    # token(String):: Generated message identifier
    # pending_request(PendingRequest):: Pending request
    #
    # === Return
    # (PendingRequest):: Stored request
    def []=(token, pending_request)
      now = Time.now
      if (now - @last_cleanup) > MIN_CLEANUP_INTERVAL
        self.reject! { |t, r| r.kind == :send_push && (now - r.receive_time) > MAX_PUSH_AGE }
        @last_cleanup = now
      end
      super
    end

    # Select cache entries of the given kind
    #
    # === Parameters
    # kind(Symbol):: Kind of request to be included: :send_push or :send_request
    #
    # === Return
    # (Hash):: Requests of specified kind
    def kind(kind)
      self.reject { |t, r| r.kind != kind}
    end

    # Get age of youngest pending request
    #
    # === Parameters
    # pending_requests(Hash):: Pending requests to be examined
    #
    # === Return
    # age(Integer):: Age of youngest request
    def self.youngest_age(pending_requests)
      now = Time.now
      age = nil
      pending_requests.each_value do |r|
        seconds = (now - r.receive_time).to_i
        age = seconds if age.nil? || seconds < age
      end
      age
    end

    # Get age of oldest pending request
    #
    # === Parameters
    # pending_requests(Hash):: Pending requests to be examined
    #
    # === Return
    # age(Integer):: Age of oldest request
    def self.oldest_age(pending_requests)
      now = Time.now
      age = nil
      pending_requests.each_value do |r|
        seconds = (now - r.receive_time).to_i
        age = seconds if age.nil? || seconds > age
      end
      age
    end

  end # PendingRequests

end # RightScale
