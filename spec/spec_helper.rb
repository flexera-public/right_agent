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

require 'rubygems'
require 'bundler/setup'

require 'rspec'
require 'flexmock'
require 'simplecov'
require 'eventmachine'
require 'fileutils'

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib', 'right_agent'))

RSpec.configure do |c|
  c.mock_with(:flexmock)
end

RightScale::Log.init

$TESTING = true
$VERBOSE = nil # Disable constant redefined warning
TEST_SOCKET_PORT = 80000

RightScale::ErrorTracker.init(RightScale::Agent, "test_agent", :trace_level => RightScale::Agent::TRACE_LEVEL)

module RightScale

  module SpecHelper

    # Create test certificate
    def issue_cert
      test_dn = { 'C'  => 'US',
                  'ST' => 'California',
                  'L'  => 'Santa Barbara',
                  'O'  => 'Agent',
                  'OU' => 'Certification Services',
                  'CN' => 'Agent test' }
      dn = DistinguishedName.new(test_dn)
      key = RsaKeyPair.new
      [ Certificate.new(key, dn, dn), key ]
    end

  end # SpecHelper

  class Log

    # Monkey path RightAgent logger to not log by default
    # Define env var RS_LOG to override this behavior and have the logger log normally
    class << self
      alias :original_method_missing :method_missing
    end

    def self.method_missing(m, *args)
      original_method_missing(m, *args) unless [:debug, :info, :warn, :warning, :error, :fatal].include?(m) && ENV['RS_LOG'].nil?
    end

  end # Log

end

# Functions for setting version per ProtocolVersionMixin
def version_cannot_put_version_in_packet; RightScale::Packet::DEFAULT_VERSION end
def version_can_put_version_in_packet; 12 end

def version_cannot_use_router_query_tags; 7 end
def version_can_use_router_query_tags; 8 end

def version_cannot_handle_request_retries; 8 end
def version_can_handle_request_retries; 9 end

def version_cannot_route_to_response_queue; 9 end
def version_can_route_to_response_queue; 10 end

def version_cannot_handle_non_nanite_ids; 9 end
def version_can_handle_non_nanite_ids; 10 end

def version_cannot_handle_multicast_result; 9 end
def version_can_handle_multicast_result; 10 end

def version_cannot_handle_msgpack_result; 11 end
def version_can_handle_msgpack_result; 12 end

def version_cannot_handle_non_delivery_result; 12 end
def version_can_handle_non_delivery_result; 13 end

def version_cannot_handle_http_result; 22 end
def version_can_handle_http_result; 23 end
