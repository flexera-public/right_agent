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

  # Agent tags management
  class AgentTagManager

    include RightSupport::Ruby::EasySingleton

    # (Agent) Agent being managed
    attr_accessor :agent

    # Retrieve current agent tags and give result to block
    #
    # === Parameters
    # options(Hash):: Request options
    #   :raw(Boolean):: true to yield raw tag response instead of deserialized tags
    #   :timeout(Integer):: timeout in seconds before giving up and yielding an error message
    #
    # === Block
    # Given block should take one argument which will be set with an array
    # initialized with the tags of this instance
    #
    # === Return
    # true:: Always return true
    def tags(options = {})
      # TODO remove use of agent identity when fully drop AMQP
      do_query(nil, @agent.mode == :http ? @agent.self_href : @agent.identity, options) do |result|
        if result.kind_of?(Hash)
          yield(result.size == 1 ? result.values.first['tags'] : [])
        else
          yield result
        end
      end
    end

    # Queries a list of servers in the current deployment which have one or more
    # of the given tags.
    #
    # === Parameters
    # tags(String, Array):: Tag or tags to query or empty
    # options(Hash):: Request options
    #   :raw(Boolean):: true to yield raw tag response instead of deserialized tags
    #   :timeout(Integer):: timeout in seconds before giving up and yielding an error message
    #
    # === Block
    # Given block should take one argument which will be set with an array
    # initialized with the tags of this instance
    #
    # === Return
    # true:: Always return true
    def query_tags(tags, options = {})
      tags = ensure_flat_array_value(tags) unless tags.nil? || tags.empty?
      do_query(tags, nil, options) { |result| yield result }
    end

    # Queries a list of servers in the current deployment which have one or more
    # of the given tags. Yields the raw response (for responding locally).
    #
    # === Parameters
    # tags(String, Array):: Tag or tags to query or empty
    # hrefs(Array):: hrefs of resources to query with empty or nil meaning all instances in deployment
    # options(Hash):: Request options
    #   :timeout(Integer):: timeout in seconds before giving up and yielding an error message
    #
    # === Block
    # Given block should take one argument which will be set with the raw response
    #
    # === Return
    # true:: Always return true
    def query_tags_raw(tags, hrefs = nil, options = {})
      tags = ensure_flat_array_value(tags) unless tags.nil? || tags.empty?
      options = options.merge(:raw => true)
      do_query(tags, hrefs, options) { |raw_response| yield raw_response }
    end

    # Add given tags to agent
    #
    # === Parameters
    # new_tags(String, Array):: Tag or tags to be added
    # options(Hash):: Request options
    #   :timeout(Integer):: timeout in seconds before giving up and yielding an error message
    #
    # === Block
    # A block is optional. If provided, should take one argument which will be set with the
    # raw response
    #
    # === Return
    # true always return true
    def add_tags(new_tags, options = {})
      new_tags = ensure_flat_array_value(new_tags) unless new_tags.nil? || new_tags.empty?
      do_update(new_tags, [], options) { |raw_response| yield raw_response if block_given? }
    end

    # Remove given tags from agent
    #
    # === Parameters
    # old_tags(String, Array):: Tag or tags to be removed
    # options(Hash):: Request options
    #   :timeout(Integer):: timeout in seconds before giving up and yielding an error message
    #
    # === Block
    # A block is optional. If provided, should take one argument which will be set with the
    # raw response
    #
    # === Return
    # true always return true
    def remove_tags(old_tags, options = {})
      old_tags = ensure_flat_array_value(old_tags) unless old_tags.nil? || old_tags.empty?
      do_update([], old_tags, options) { |raw_response| yield raw_response if block_given? }
    end

    # Clear all agent tags
    #
    # === Parameters
    # options(Hash):: Request options
    #   :timeout(Integer):: timeout in seconds before giving up and yielding an error message
    #
    # === Block
    # Given block should take one argument which will be set with the raw response
    #
    # === Return
    # true::Always return true
    def clear(options = {})
      do_update([], @agent.tags, options) { |raw_response| yield raw_response }
    end

    private

    def agent_check
      raise ArgumentError.new("Must set agent= before using tag manager") unless @agent
    end

    # Runs a tag query with an optional list of tags.
    #
    # === Parameters
    # tags(Array):: Tags to query or empty or nil
    # hrefs(Array):: hrefs of resources to query with empty or nil meaning all instances in deployment
    # options(Hash):: Request options
    #   :raw(Boolean):: true to yield raw tag response instead of unserialized tags
    #   :timeout(Integer):: timeout in seconds before giving up and yielding an error message
    #
    # === Block
    # Given block should take one argument which will be set with an array
    # initialized with the tags of this instance
    #
    # === Return
    # true:: Always return true
    def do_query(tags = nil, hrefs = nil, options = {})
      raw = options[:raw]
      timeout = options[:timeout]

      request_options = {}
      request_options[:timeout] = timeout if timeout

      agent_check
      payload = {:agent_identity => @agent.identity}
      payload[:tags] = ensure_flat_array_value(tags) unless tags.nil? || tags.empty?
      # TODO remove use of agent identity when fully drop AMQP
      if @agent.mode == :http
        payload[:hrefs] = ensure_flat_array_value(hrefs) unless hrefs.nil? || hrefs.empty?
      else
        payload[:agent_ids] = ensure_flat_array_value(hrefs) unless hrefs.nil? || hrefs.empty?
      end
      request = RightScale::RetryableRequest.new("/router/query_tags", payload, request_options)
      request.callback { |result| yield raw ? request.raw_response : result }
      request.errback do |message|
        ErrorTracker.log(self, "Failed to query tags (#{message})")
        yield((raw ? request.raw_response : nil) || message)
      end
      request.run
      true
    end

    # Runs a tag update with a list of new or old tags
    #
    # === Parameters
    # new_tags(Array):: new tags to add or empty
    # old_tags(Array):: old tags to remove or empty
    # block(Block):: optional callback for update response
    #
    # === Block
    # A block is optional. If provided, should take one argument which will be set with the
    # raw response
    #
    # === Return
    # true:: Always return true
    def do_update(new_tags, old_tags, options = {}, &block)
      agent_check
      raise ArgumentError.new("Cannot add and remove tags in same update") if new_tags.any? && old_tags.any?
      tags = @agent.tags
      tags += new_tags
      tags -= old_tags
      tags.uniq!

      if new_tags.any?
        request = RightScale::RetryableRequest.new("/router/add_tags", {:tags => new_tags}, options)
      elsif old_tags.any?
        request = RightScale::RetryableRequest.new("/router/delete_tags", {:tags => old_tags}, options)
      else
        return
      end

      if block
        # Always yield raw response
        request.callback do |_|
          # Refresh agent's copy of tags on successful update
          @agent.tags = tags
          block.call(request.raw_response)
        end
        request.errback { |message| block.call(request.raw_response || message) }
      end
      request.run
      true
    end

    # Ensures value is a flat array, making an array from the single value if necessary
    #
    # === Parameters
    # value(Object):: any kind of value
    #
    # === Return
    # result(Array):: flat array value
    def ensure_flat_array_value(value)
      value = Array(value).flatten.compact
    end

  end # AgentTagManager

end # RightScale
