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
require 'right_support'
require 'yaml'

# load definition for File.normalize_path, etc.
require ::File.expand_path('../monkey_patches', __FILE__)

unless defined?(RIGHT_AGENT_BASE_DIR)
  RIGHT_AGENT_BASE_DIR = ::File.normalize_path('..', __FILE__)
end

# require minimal gems needed to create a CommandClient and send a command.
#
# FIX: agent_controller is currently the only minimal-load use case so these
# requires are oriented toward that. any additional use cases may require a
# rethink of minimal loading.
require ::File.normalize_path('agent_config', RIGHT_AGENT_BASE_DIR)
require ::File.normalize_path('command', RIGHT_AGENT_BASE_DIR)
require ::File.normalize_path('log', RIGHT_AGENT_BASE_DIR)
require ::File.normalize_path('pid_file', RIGHT_AGENT_BASE_DIR)
require ::File.normalize_path('serialize/serializable', RIGHT_AGENT_BASE_DIR)
