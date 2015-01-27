#
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

# Wrap EventMachine to support automatically spawning of fiber before executing
# associated block so that if block yields its fiber it is not the root fiber
module EventMachineSpawn
  @fiber_pool = nil

  def self.fiber_pool
    @fiber_pool
  end

  def self.fiber_pool=(value)
    @fiber_pool = value
  end

  def self.execute(&block)
    @fiber_pool ? @fiber_pool.spawn(&block) : yield
  end

  def self.run(*args, &block)
    EM.run(*args) { @fiber_pool ? @fiber_pool.spawn(&block) : yield }
  end

  def self.next_tick(*args, &block)
    EM.next_tick(*args) { @fiber_pool ? @fiber_pool.spawn(&block) : yield }
  end

  def self.wait(seconds)
    if @fiber_pool
      fiber = Fiber.current
      EM.add_timer(seconds) { fiber.resume }
      Fiber.yield
    else
      sleep(seconds)
    end
  end

  def self.add_timer(*args, &block)
    EM.add_timer(*args) { @fiber_pool ? @fiber_pool.spawn(&block) : yield }
  end

  def self.add_periodic_timer(*args, &block)
    EM.add_periodic_timer(*args) { @fiber_pool ? @fiber_pool.spawn(&block) : yield }
  end

  class Timer
    def self.new(*args, &block)
      EM::Timer.new(*args) { EM_S.fiber_pool ? EM_S.fiber_pool.spawn(&block) : yield }
    end
  end

  class PeriodicTimer
    def self.new(*args, &block)
      EM::PeriodicTimer.new(*args) { EM_S.fiber_pool ? EM_S.fiber_pool.spawn(&block) : yield }
    end
  end
end

# Alias for EventMachineSpawn
EM_S = EventMachineSpawn
