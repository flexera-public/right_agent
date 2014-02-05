##
# Copyright (c) 2014 RightScale Inc
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

  # Mixin for testing for availability of features in agents based on protocol version
  module ProtocolVersionMixin

    # Test whether given version of agent has the protocol version embedded in each
    # packet (this is generally inferred by the version in the received packet not being
    # Packet::DEFAULT_VERSION, which is true of all with version >= 12)
    def can_put_version_in_packet?(version);      version && version != 0 end
    def self.can_put_version_in_packet?(version); version && version != 0 end

    # Test whether given version of agent uses /mapper/query_tags rather than the
    # deprecated TagQuery packet
    def can_use_mapper_query_tags?(version);      version && version >= 8 end
    def self.can_use_mapper_query_tags?(version); version && version >= 8 end

    # Test whether given version of agent can handle a request that is being retried
    # as indicated by a retries count in the Request packet
    def can_handle_request_retries?(version);      version && version >= 9 end
    def self.can_handle_request_retries?(version); version && version >= 9 end

    # Test whether given version of agent can handle serialized identity and queue name
    # that does not incorporate 'nanite'
    def can_handle_non_nanite_ids?(version);      version && version >= 10 end
    def self.can_handle_non_nanite_ids?(version); version && version >= 10 end

    # Test whether given version of agent supports routing results to mapper response queue
    # rather than to the identity queue of the mapper that routed the request
    def can_route_to_response_queue?(version);      version && version >= 10 end
    def self.can_route_to_response_queue?(version); version && version >= 10 end

    # Test whether given version of agent can handle receipt of a result containing an
    # OperationResult with MULTICAST status
    def can_handle_multicast_result?(version);      version && [10, 11].include?(version) end
    def self.can_handle_multicast_result?(version); version && [10, 11].include?(version) end

    # Test whether given version of agent can handle msgpack encoding
    def can_handle_msgpack_result?(version);      version && version >= 12 end
    def self.can_handle_msgpack_result?(version); version && version >= 12 end

    # Test whether given version of agent can handle receipt of a result containing an
    # OperationResult with NON_DELIVERY status
    def can_handle_non_delivery_result?(version);      version && version >= 13 end
    def self.can_handle_non_delivery_result?(version); version && version >= 13 end

    # Test whether given version of agent can handle HTTP communication mode
    def can_handle_http?(version);      version && version >= 23 end
    def self.can_handle_http?(version); version && version >= 23 end

  end # ProtocolVersionMixin

end # RightScale
