# Copyright (c) 2009-2011 RightScale, Inc, All Rights Reserved Worldwide.
#
# THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO RIGHTSCALE
# AND CONSTITUTES A VALUABLE TRADE SECRET.  Any unauthorized use,
# reproduction, modification, or disclosure of this program is
# strictly prohibited.  Any use of this program by an authorized
# licensee is strictly subject to the terms and conditions,
# including confidentiality obligations, set forth in the applicable
# License Agreement between RightScale.com, Inc. and
# the licensee.

require 'rubygems'

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib', 'bundler_support'))
RightScale::BundlerSupport.activate

require 'flexmock'
require 'rspec'
require 'eventmachine'
require 'fileutils'

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib', 'right_infrastructure_agent'))

RSpec.configure do |c|
  c.mock_with(:flexmock)
end

RightScale::Log.init

$TESTING = true
$VERBOSE = nil # Disable constant redefined warning
TEST_SOCKET_PORT = 80000

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
