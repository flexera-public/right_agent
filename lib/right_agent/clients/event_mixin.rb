##
# Copyright (c) 2014 RightScale Inc
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

  # Mixin for event hash usage
  module EventMixin

    # Mix this module into its own eigenclass to make the module-instance methods
    # become callable as module methods
    extend self

    # Display text for an event
    #
    # @param [Hash, String, Numeric] event with keys symbolized, or event UUID string,
    #   or numeric event ID
    #
    # @return [String] log text
    def event_trace(event)
      if event.is_a?(Hash)
        id = event[:id] && ":#{event[:id]}"
        "<#{event[:uuid]}#{id}>"
      elsif event.is_a?(String)
        "<#{event}>"
      else
        "<..:#{event}>"
      end
    end

    # Display text for an event
    #
    # @param [Hash] event with keys symbolized
    #
    # @return [String] log text
    def event_text(event)
      text = event_trace(event)
      text << " #{event[:type]}" if event[:type]
      text << " #{event[:path]}" if event[:path]
      text << " from #{event[:source]}" if event[:source]
      text << " to #{event[:to]}" if event[:to]
      text
    end

  end # EventMixin

end # RightScale