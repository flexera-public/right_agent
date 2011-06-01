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
require 'right_agent'

RIGHT_INFRASTRUCTURE_AGENT_BASE_DIR = File.normalize_path(File.join(File.dirname(__FILE__), 'right_infrastructure_agent'))
require File.join(RIGHT_INFRASTRUCTURE_AGENT_BASE_DIR, 'exception_mailer.rb')
require File.join(RIGHT_INFRASTRUCTURE_AGENT_BASE_DIR, 'infrastructure_packets')
require File.join(RIGHT_INFRASTRUCTURE_AGENT_BASE_DIR, 'infrastructure_agent')
