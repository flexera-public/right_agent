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

module RightScale
  class Exceptions
    # Capability not currently supported
    class NotSupported < Exception; end

    # Internal application error
    class Application < RuntimeError
      attr_reader :nested_exception
      def initialize(message, nested_exception = nil)
        @nested_exception = nested_exception
        super(message)
      end
    end

    # Invalid command or method argument
    class Argument < RuntimeError; end

    # Agent command IO error
    class IO < RuntimeError; end

    # Agent compute platform error
    class PlatformError < StandardError; end

    # Cannot connect or lost connection to external resource
    class ConnectivityFailure < RuntimeError
      attr_reader :nested_exception
      def initialize(message, nested_exception = nil)
        @nested_exception = nested_exception
        super(message)
      end
    end

    # Request failed but potentially will succeed if retried
    class RetryableError < RuntimeError
      attr_reader :nested_exception
      def initialize(message, nested_exception = nil)
        @nested_exception = nested_exception
        super(message)
      end
    end

    # Database query failed
    class QueryFailure < RuntimeError
      attr_reader :nested_exception
      def initialize(message, nested_exception = nil)
        @nested_exception = nested_exception
        super(message)
      end
    end
  end
end
