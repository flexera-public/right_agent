#
# Copyright (c) 2011 RightScale Inc
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
require 'eventmachine'
require 'fileutils'
require 'yaml'
require 'right_support'

# Load ruby interpreter monkey-patches first (to ensure File.normalize_path is defined, etc.).
require File.expand_path(File.join(File.dirname(__FILE__), 'monkey_patches', 'ruby_patch'))

unless defined?(RIGHT_AGENT_BASE_DIR)
  RIGHT_AGENT_BASE_DIR = File.normalize_path(File.dirname(__FILE__))
end

# require minimal gems needed to create a CommandClient and send a command.
#
# FIX: agent_controller is currently the only minimal-load use case so these
# requires are oriented toward that. any additional use cases may require a
# rethink of minimal loading.
require File.normalize_path(File.join(RIGHT_AGENT_BASE_DIR, 'agent_config'))
require File.normalize_path(File.join(RIGHT_AGENT_BASE_DIR, 'command'))
require File.normalize_path(File.join(RIGHT_AGENT_BASE_DIR, 'log'))
require File.normalize_path(File.join(RIGHT_AGENT_BASE_DIR, 'pid_file'))
require File.normalize_path(File.join(RIGHT_AGENT_BASE_DIR, 'serialize', 'serializable'))
