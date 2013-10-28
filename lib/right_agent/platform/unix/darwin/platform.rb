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

require ::File.expand_path('../../platform', __FILE__)

module RightScale

  # Mac OS specific implementation
  class Platform

    # Provides utilities for managing volumes (disks).
    class VolumeManager

      # Overrides base VolumeManager#volumes
      def volumes(conditions = nil)
        raise ::NotImplementedError, 'Not yet supporting Mac OS volume query'
      end

      # Overrides base VolumeManager#mount_volume
      def mount_volume(volume, mountpoint)
        raise ::NotImplementedError, 'Not yet supporting Mac OS volume mounting'
      end
    end

    class Shell

      # Overrides base Shell#uptime
      def uptime
        return (Time.now.to_i.to_f - booted_at.to_f) rescue 0.0
      end

      # Overrides base Shell#booted_at
      def booted_at
        output_text = execute('sysctl kern.boottime')
        match = /sec = ([0-9]+)/.match(output_text)
        if match && (match[1].to_i > 0)
          return match[1].to_i
        else
          return nil
        end
      end
    end # Shell

    class Controller

      # Overrides base Controller#reboot
      def reboot
        execute('shutdown -r now 2>&1')
        true
      end

      # Overrides base Controller#shutdown
      def shutdown
        execute('shutdown -h now 2>&1')
        true
      end
    end # Controller

    class Installer

      # Overrides base Installer#install
      def install(packages)
        raise ::NotImplementedError, 'Not yet supporting Mac OS package install'
      end
    end # Installer

    private

    # Overrides base Platform#initialize_species
    def initialize_species
      @flavor = 'mac_os_x'
      begin
        @release = execute('sw_vers -productVersion 2>&1').strip
        @codename = '' # TEAL FIX cannot find a way to query osx codename by CLI
      rescue ::RightScale::Platform::CommandError
        @release = @codename = 'unknown'
      end
      true
    end

  end # Platform

end # RightScale
