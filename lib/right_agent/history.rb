#
# Copyright (c) 2009-2012 RightScale Inc
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

require 'fileutils'

module RightScale

  # Agent history manager
  class History

    # Initialize history
    #
    # === Parameters
    # identity(String):: Serialized agent identity
    # pid(Integer):: Process ID of agent, defaults to ID if current process
    def initialize(identity, pid = nil)
      @pid = pid || Process.pid
      @history = File.join(AgentConfig.pid_dir, identity + ".history")
    end

    # Append event to history file
    #
    # === Parameters
    # event(Object):: Event to be stored in the form String or {String => Object},
    #   where String is the event name and Object is any associated JSON-encodable data
    #
    # === Return
    # true:: Always return true
    def update(event)
      @last_update = {:time => Time.now.to_i, :pid => @pid, :event => event}
      FileUtils.mkdir_p(File.dirname(@history)) unless File.exists?(File.dirname(@history))
      File.open(@history, "a") { |f| f.puts @last_update.to_json }
      true
    end

    # Load events from history file
    #
    # === Return
    # events(Array):: List of historical events with each being a hash of
    #   :time(Integer):: Time in seconds in Unix-epoch when event occurred
    #   :pid(Integer):: Process id of agent recording the event
    #   :event(Object):: Event object in the form String or {String => Object},
    #     where String is the event name and Object is any associated JSON-encodable data
    def load
      events = []
      File.open(@history, "r") { |f| events = f.readlines.map { |l| JSON.parser.new(l, JSON.load_default_options).parse } } if File.readable?(@history)
      events
    end

    # Analyze history to determine service attributes like uptime and restart/crash counts
    #
    # === Return
    # (Hash):: Results of analysis
    #   :uptime(Integer):: Current time in service
    #   :total_uptime(Integer):: Total time in service (but if there were crashes
    #     this total includes recovery time, which makes it inaccurate)
    #   :restarts(Integer|nil):: Number of restarts, if any
    #   :graceful_exits(Integer|nil):: Number of graceful terminations, if any
    #   :crashes(Integer|nil):: Number of crashes, if any
    #   :last_crash_time(Integer|nil):: Time in seconds in Unix-epoch when last crash occurred, if any
    #   :crashed_last(Boolean):: Whether crashed last time it was started
    def analyze_service
      now = Time.now.to_i
      if @last_analysis && @last_event == @last_update
        delta = now - @last_analysis_time
        @last_analysis[:uptime] += delta
        @last_analysis[:total_uptime] += delta
      else
        last_run = last_crash = @last_event = {:time => 0, :pid => 0, :event => nil}
        restarts = graceful_exits = crashes = accumulated_uptime = 0
        crashed_last = false
        load.each do |event|
          event = SerializationHelper.symbolize_keys(event)
          case event[:event]
          when "start"
            case @last_event[:event]
            when "stop", "graceful exit"
              restarts += 1
            when "start"
              crashes += 1
              last_crash = event
              crashed_last = true
            when "run"
              crashes += 1
              last_crash = event
              crashed_last = true
              # Accumulating uptime here although this will wrongly include recovery time
              accumulated_uptime += (event[:time] - @last_event[:time])
            end
          when "run"
            last_run = event
          when "stop"
            crashed_last = false
            if @last_event[:event] == "run" && @last_event[:pid] == event[:pid]
              accumulated_uptime += (event[:time] - @last_event[:time])
            end
          when "graceful exit"
            crashed_last = false
            graceful_exits += 1
          else
            next
          end
          @last_event = event
        end
        current_uptime = last_run[:pid] == @pid ? (now - last_run[:time]) : 0
        @last_analysis = {
          :uptime => current_uptime,
          :total_uptime => accumulated_uptime + current_uptime
        }
        if restarts > 0
          @last_analysis[:restarts] = restarts
          @last_analysis[:graceful_exits] = graceful_exits
        end
        if crashes > 0
          @last_analysis[:crashes] = crashes
          @last_analysis[:last_crash_time] = last_crash[:time]
          @last_analysis[:crashed_last] = crashed_last
        end
      end
      @last_analysis_time = now
      @last_analysis
    end

  end # History

end # RightScale
