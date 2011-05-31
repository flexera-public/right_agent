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
#

module RightScale

  # Individual cookbook
  class Cookbook

    include Serializable

    # (String) Cookbook SHA hash.
    attr_accessor :hash

    # (String) Authentication token
    attr_accessor :token

    # (String) User readable cookbook name
    attr_accessor :name

    # Initialize fields from given arguments
    def initialize(*args)
      @hash  = args[0] if args.size > 0
      @token = args[1] if args.size > 1
      @name  = args[2] if args.size > 2
    end

    # Array of serialized fields given to constructor
    def serialized_members
      [ @hash, @token, @name ]
    end

    # Human friendly name used for audits
    #
    # === Return
    # name(String):: Cookbook repository display name
    def display_name
      name = "Cookbook #{@name}:#{@hash}"
    end
    alias :to_s :display_name
  end
end
