#--  -*- mode: ruby; encoding: utf-8 -*-
# Copyright: Copyright (c) 2011 RightScale, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# 'Software'), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#++

require 'uri'

module RightScale
  # Specialization of ReposeDownloader for downloading via an HTTP
  # proxy.
  class ReposeProxyDownloader < ReposeDownloader
    # Environment variables to examine for proxy settings, in order.
    PROXY_ENVIRONMENT_VARIABLES = ['HTTPS_PROXY', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY']

    # Prepare to request a resource from the Repose mirror.  Arguments
    # are the same as ReposeDownloader#new.
    def initialize(*args)
      super
      useful_variable = PROXY_ENVIRONMENT_VARIABLES.detect {|v| ENV.has_key?(v)}
      @proxy = URI.parse(ENV[useful_variable])
    end

    # Given a sequence of preferred hostnames, store an ordered
    # sequence of hostnames from which to attempt cookbook download.
    # Unfortunately most proxies won't let you connect to a specific
    # IP, instead forcing a DNS lookup, so we don't do the IP lookup
    # here which means our high availability guarantees are not valid.
    #
    # === Parameters
    # hostnames(Array):: hostnames
    #
    # === Return
    # true:: always returns true
    def self.discover_repose_servers(hostnames)
      @@index = 0
      @@ips = []
      @@hostnames = {}
      hostnames = [hostnames] unless hostnames.respond_to?(:each)
      @@ips = hostnames
      hostnames.each do |name|
        @@hostnames[name] = name
      end
      true
    end

    protected

    # Make a Rightscale::HttpConnection for later use, respecting the
    # proxy settings.
    def make_connection(host)
      Rightscale::HttpConnection.new(:user_agent => "RightLink v#{RightLinkConfig.protocol_version}",
                                     :logger => @logger,
                                     :proxy_host => @proxy.host,
                                     :proxy_port => @proxy.port,
                                     :proxy_username => @proxy.user,
                                     :proxy_password => @proxy.password,
                                     :exception => ReposeConnectionFailure,
                                     :fail_if_ca_mismatch => true,
                                     :ca_file => get_ca_file)
    end
  end
end