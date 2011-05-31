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

require File.join(File.dirname(__FILE__), 'platform')
RightScale::Platform.load_platform_specific # To define 'File.normalize_path'

module RightScale

  # Container for RightAgent configuration data
  class AgentConfig

    # Current agent protocol version
    def self.protocol_version
      15
    end

    # Root path to agent files
    def self.root_path
      File.dirname(File.expand_path(File.join(__FILE__, '..', '..')))
    end

    # Path to directory containing the certificates used to sign and encrypt all
    # outgoing messages as well as to check the signature and decrypt any incoming
    # messages. This directory should contain at least:
    #  - The agent private key ('<name of agent>.key')
    #  - The agent public certificate ('<name of agent>.cert')
    #  - The mapper public certificate ('mapper.cert')
    def self.certs_dir
      File.join(root_path, 'certs')
    end

    # Host platform configuration
    def self.platform
      Platform
    end

  end # AgentConfig

end # RightScale
