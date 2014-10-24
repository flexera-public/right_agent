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

CLIENTS_BASE_DIR = File.join(File.dirname(__FILE__), 'clients')

unless defined?(Fiber)
  # To avoid load errors when using pre-1.9 ruby
  class Fiber
    def self.current; nil end
    def self.yield; [] end
  end
end

require File.normalize_path(File.join(CLIENTS_BASE_DIR, 'non_blocking_client'))
require File.normalize_path(File.join(CLIENTS_BASE_DIR, 'blocking_client'))
require File.normalize_path(File.join(CLIENTS_BASE_DIR, 'balanced_http_client'))
require File.normalize_path(File.join(CLIENTS_BASE_DIR, 'base_retry_client'))
require File.normalize_path(File.join(CLIENTS_BASE_DIR, 'auth_client'))
require File.normalize_path(File.join(CLIENTS_BASE_DIR, 'api_client'))
require File.normalize_path(File.join(CLIENTS_BASE_DIR, 'router_client'))
require File.normalize_path(File.join(CLIENTS_BASE_DIR, 'right_http_client'))
require File.normalize_path(File.join(CLIENTS_BASE_DIR, 'broker_http_client'))
