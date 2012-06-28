#
# Copyright (c) 2012 RightScale Inc
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

  # Cache for requests that have been dispatched recently
  # This cache is intended for use in checking for duplicate requests
  # Since this is a local cache, it is not usable for requests received from a shared queue
  class DispatchedCache

    # Maximum number of seconds to retain a dispatched request in cache
    # This must be greater than the maximum possible retry timeout to avoid
    # duplicate execution of a request
    MAX_AGE = 12 * 60 * 60

    # Initialize cache
    #
    # === Parameters
    # identity(String):: Serialized identity of agent
    def initialize(identity)
      @identity = identity
      @cache = {}
      @lru = []
      @max_age = MAX_AGE
    end

    # Store dispatched request token in cache unless actor method is idempotent
    # Ignore request if from shared queue
    #
    # === Parameters
    # token(String):: Generated message identifier
    # shared_queue(String|nil):: Name of shared queue if being dispatched from a shared queue
    # idempotent(Boolean):: Whether the actor method to be executed is idempotent
    #
    # === Return
    # true:: Always return true
    def store(token, shared_queue, idempotent)
      if token && !idempotent && shared_queue.nil?
        now = Time.now.to_i
        if @cache.has_key?(token)
          @cache[token] = now
          @lru.push(@lru.delete(token))
        else
          @cache[token] = now
          @lru.push(token)
          @cache.delete(@lru.shift) while (now - @cache[@lru.first]) > @max_age
        end
      end
      true
    end

    # Determine whether request has already been serviced
    #
    # === Parameters
    # token(String):: Generated message identifier
    #
    # === Return
    # (String|nil):: Identity of agent that already serviced request, or nil if none
    def serviced_by(token)
      if @cache[token]
        @cache[token] = Time.now.to_i
        @lru.push(@lru.delete(token))
        @identity
      end
    end

    # Get local cache statistics
    #
    # === Return
    # stats(Hash|nil):: Current statistics, or nil if cache empty
    #   "local total"(Integer):: Total number in local cache, or nil if none
    #   "local max age"(String):: Time since oldest local cache entry created or updated
    def stats
      if (s = size) > 0
        now = Time.now.to_i
        {
          "local total" => s,
          "local max age" => RightSupport::Stats.elapsed(now - @cache[@lru.first])
        }
      end
    end

    # Get local cache size
    #
    # === Return
    # (Integer):: Number of cache entries
    def size
      @cache.size
    end

  end # DispatchedCache

end # RightScale
