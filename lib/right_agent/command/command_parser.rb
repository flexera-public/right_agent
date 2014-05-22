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

  class CommandParser

    # Register callback block
    #
    # === Block
    # Block that will get called back whenever a command is successfully parsed
    #
    # === Raise
    # (ArgumentError): If block is missing
    def initialize &block
      raise ArgumentError, 'Missing handler block' unless block
      @callback = block
      @buildup = ''
    end

    # Parse given input
    # May cause multiple callbacks if multiple commands are successfully parsed
    # Callback happens in next EM tick
    #
    # === Parameters
    # chunk(String):: Chunck of serialized command(s) to be parsed
    #
    # === Return
    # true:: If callback was called at least once
    # false:: Otherwise
    def parse_chunk(chunk)
      @buildup << chunk
      chunks = @buildup.split(CommandSerializer::SEPARATOR, -1)
      if (do_call = chunks.size > 1)
        commands = []
        (0..chunks.size - 2).each do |i|
          begin
            commands << CommandSerializer.load(chunks[i])
          rescue StandardError => e
            # log any exceptions caused by serializing individual chunks instead
            # of halting EM. each command is discrete so we need to keep trying
            # so long as there are more commands to process (although subsequent
            # commands may lack context if previous commands failed).
            Log.error("Failed parsing command chunk", e, :trace)
          end
        end
        commands.each do |cmd|
          EM.next_tick do
            begin
              @callback.call(cmd)
            rescue Exception => e
              # log any exceptions raised by callback instead of halting EM.
              Log.error("Failed executing parsed command", e, :trace)
            end
          end
        end
        @buildup = chunks.last
      end
      do_call
    rescue StandardError => e
      # log any other exceptions instead of halting EM.
      Log.error("Failed parsing command chunk", e, :trace)
    end

  end # CommandParser

end # RightScale
