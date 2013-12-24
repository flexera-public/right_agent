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

module RightScale

  # Abstract base class for authorization client
  class AuthClient

    # When there is an unexpected failure during authorization
    class AuthorizationError < RuntimeError; end

    def initialize(options = {})
      raise NotImplementedError.new("#{self.class.name} is an abstract class.")
    end

    # Identity of agent using this client
    #
    # @return [String] identity
    def identity
      nil
    end

    # Header to be added to HTTP request for authorization
    #
    # @return [Hash] value to be inserted into request header
    #
    # @raise [RightScale::Exceptions::Unauthorized] not authorized
    def session_header
      nil
    end

    # URL for accessing RightApi
    #
    # @return [String] base URL
    #
    # @raise [RightScale::Exceptions::Unauthorized] not authorized
    def api_url
      nil
    end

    # URL for accessing RightNet router
    #
    # @return [String] base URL
    #
    # @raise [RightScale::Exceptions::Unauthorized] not authorized
    def router_url
      nil
    end

    # Protocol to be used
    #
    # @return [String] "http" or "amqp"
    #
    # @raise [RightScale::Exceptions::Unauthorized] not authorized
    def protocol
      nil
    end

    # An HTTP request received a redirect response
    # Infer from this that need to re-authorize
    #
    # @param [String] location to which response indicated to redirect
    #
    # @return [TrueClass] always true
    def redirect(location)
      true
    end

    # Take any actions necessary to quiesce client interaction in preparation
    # for agent termination but allow any active requests to complete
    #
    # @return [TrueClass] always true
    def close
      true
    end

    # Current statistics for this client
    #
    # @param [Boolean] reset the statistics after getting the current ones
    #
    # @return [Hash] statistics conforming to RightSupport::Stats
    def stats(reset = false)
      nil
    end

  end # AuthClient

end # RightScale