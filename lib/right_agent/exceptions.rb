#
# Copyright (c) 2009-2013 RightScale Inc
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

  class Exceptions

    # Base exception for use in nesting exceptions
    class NestedException < StandardError
      attr_reader :nested_exception

      # Exception message and optional nested exception or string
      def initialize(message, nested_exception = nil)
        @nested_exception = nested_exception
        super(message)
      end
    end

    # Internal application error
    class Application < StandardError; end

    # Agent command IO error
    class IO < RuntimeError; end

    # Agent compute platform error
    class PlatformError < StandardError; end

    # Terminating service
    class Terminating < RuntimeError; end

    # Not authorized to make request
    class Unauthorized < NestedException
      def initialize(message, nested_exception = nil)
        super(message, nested_exception)
      end
    end

    # Cannot connect to service, lost connection to it, or it is out of service or too busy to respond
    class ConnectivityFailure < NestedException
      def initialize(message, nested_exception = nil)
        super(message, nested_exception)
      end
    end

    # Request failed but potentially will succeed if retried
    class RetryableError < NestedException
      def initialize(message, nested_exception = nil)
        super(message, nested_exception)
      end
    end

    # Database query failed
    class QueryFailure < NestedException
      def initialize(message, nested_exception = nil)
        super(message, nested_exception)
      end
    end

    # Error internal to specified server
    class InternalServerError < NestedException
      attr_reader :server
      def initialize(message, server, nested_exception = nil)
        @server = server
        super(message, nested_exception)
      end
    end
  end
end
