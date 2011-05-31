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
require 'amqp'
require 'mq'
require 'json'
require 'yaml'
require 'openssl'

# Cannot use File.normalize because not yet defined
require File.join(File.dirname(__FILE__), 'right_agent', 'agent_config')

RIGHT_AGENT_BASE_DIR = File.normalize_path(File.join(File.dirname(__FILE__), 'right_agent'))
require File.join(RIGHT_AGENT_BASE_DIR, 'packets')
require File.join(RIGHT_AGENT_BASE_DIR, 'console')
require File.join(RIGHT_AGENT_BASE_DIR, 'daemonize')
require File.join(RIGHT_AGENT_BASE_DIR, 'pid_file')
require File.join(RIGHT_AGENT_BASE_DIR, 'exceptions')
require File.join(RIGHT_AGENT_BASE_DIR, 'multiplexer')
require File.join(RIGHT_AGENT_BASE_DIR, 'log')
require File.join(RIGHT_AGENT_BASE_DIR, 'tracer')
require File.join(RIGHT_AGENT_BASE_DIR, 'audit_formatter')
require File.join(RIGHT_AGENT_BASE_DIR, 'serialize')
require File.join(RIGHT_AGENT_BASE_DIR, 'security')
require File.join(RIGHT_AGENT_BASE_DIR, 'operation_result')
require File.join(RIGHT_AGENT_BASE_DIR, 'subprocess')
require File.join(RIGHT_AGENT_BASE_DIR, 'stats_helper')
require File.join(RIGHT_AGENT_BASE_DIR, 'broker_client')
require File.join(RIGHT_AGENT_BASE_DIR, 'ha_broker_client')
require File.join(RIGHT_AGENT_BASE_DIR, 'command')
require File.join(RIGHT_AGENT_BASE_DIR, 'agent')
