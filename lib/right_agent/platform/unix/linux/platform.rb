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

  # Linux specific implementation
  class Platform

    FEDORA_REL = '/etc/fedora-release'
    FEDORA_SIG = /Fedora release ([0-9]+) \((.*)\)/

    # Is this machine running Ubuntu?
    #
    # @return [TrueClass|FalseClass] true if Linux flavor is Ubuntu
    def ubuntu?
      !!(@flavor =~ /ubuntu/)
    end

    # Is this machine running CentOS?
    #
    # @return [TrueClass|FalseClass] true if Linux flavor is CentOS
    def centos?
      !!(@flavor =~ /centos/)
    end

    # Is this machine running Suse?
    #
    # @return [TrueClass|FalseClass] true if Linux flavor is Suse
    def suse?
      !!(@flavor =~ /suse/)
    end

    # Is this machine running RHEL?
    #
    # @return [TrueClass|FalseClass] true if Linux flavor is RHEL
    def rhel?
      !!(@flavor =~ /redhatenterpriseserver/)
    end

    # Provides utilities for managing volumes (disks).
    class VolumeManager

      # Overrides base VolumeManager#volumes
      def volumes(conditions = nil)
        blkid_resp = execute('blkid 2>&1')
        return parse_volumes(blkid_resp, conditions)
      rescue ::RightScale::Platform::CommandError => e
        raise VolumeError, "Failed to list volumes: #{e.message}"
      end

      # Overrides base VolumeManager#mount_volume
      def mount_volume(volume, mountpoint)
        unless volume.is_a?(::Hash) && volume[:device]
          raise ::ArgumentError, "Invalid volume argument = #{volume.inspect}"
        end
        mount_list_output = nil
        begin
          mount_list_output = execute('mount 2>&1')
        rescue ::RightScale::Platform::CommandError => e
          raise VolumeError, "Failed interrogation of current mounts: #{e.message}"
        end

        device_match = /^#{volume[:device]} on (.+?)\s/.match(mount_list_output)
        mountpoint_from_device_match = device_match ? device_match[1] : mountpoint
        unless (mountpoint_from_device_match && mountpoint_from_device_match == mountpoint)
          raise VolumeError,
                "Attempted to mount volume \"#{volume[:device]}\" at \"#{mountpoint}\" but it was already mounted at #{mountpoint_from_device_match}"
        end

        mountpoint_match = /^(.+?) on #{mountpoint}/.match(mount_list_output)
        device_from_mountpoint_match = mountpoint_match ? mountpoint_match[1] : volume[:device]
        unless (device_from_mountpoint_match && device_from_mountpoint_match == volume[:device])
          raise VolumeError.new("Attempted to mount volume \"#{volume[:device]}\" at \"#{mountpoint}\" but \"#{device_from_mountpoint_match}\" was already mounted there.")
        end

        # The volume is already mounted at the correct mountpoint
        return true if /^#{volume[:device]} on #{mountpoint}/.match(mount_list_output)

        # TODO: Maybe validate that the mountpoint is valid *nix path?
        begin
          execute("mount -t #{volume[:filesystem].strip} #{volume[:device]} #{mountpoint} 2>&1")
        rescue ::RightScale::Platform::CommandError => e
          raise VolumeError, "Failed to mount volume to \"#{mountpoint}\" with device \"#{volume[:device]}\": #{e.message}"
        end
        true
      end

      private

      # Parses raw output from `blkid` into a hash of volumes.
      #
      # The hash will contain the device name with a key of :device, and each
      # key value pair for the device.  In order to keep parity with the Windows
      # VolumeManager.parse_volumes method, the :type key will be duplicated as
      # :filesystem
      #
      # Example of raw output from `blkid`
      #  /dev/xvdh1: SEC_TYPE="msdos" LABEL="METADATA" UUID="681B-8C5D" TYPE="vfat"
      #  /dev/xvdb1: LABEL="SWAP-xvdb1" UUID="d51fcca0-6b10-4934-a572-f3898dfd8840" TYPE="swap"
      #  /dev/xvda1: UUID="f4746f9c-0557-4406-9267-5e918e87ca2e" TYPE="ext3"
      #  /dev/xvda2: UUID="14d88b9e-9fe6-4974-a8d6-180acdae4016" TYPE="ext3"
      #
      # @param [String] output_text from blkid
      # @param [Hash] conditions to match (Default = no conditions)
      #
      # @return [Array] volume info as an array of hashes or empty
      #
      # @raise [ParserError] on failure to parse volume list
      def parse_volumes(output_text, conditions = nil)
        results = []
        output_text.lines.each do |line|
          volume = {}
          line_regex = /^([\/a-z0-9_\-\.]+):(.*)/
          volmatch = line_regex.match(line)
          raise ParserError.new("Failed to parse volume info from #{line.inspect} using #{line_regex.inspect}") unless volmatch
          volume[:device] = volmatch[1]
          volmatch[2].split(' ').each do |pair|
            pair_regex = /([a-zA-Z_\-]+)=(.*)/
            match = pair_regex.match(pair)
            raise ParserError.new("Failed to parse volume info from #{pair} using #{pair_regex.inspect}") unless match
            volume[:"#{match[1].downcase}"] = match[2].gsub('"', '')
            # Make this as much like the windows output as possible
            if match[1] == 'TYPE'
              volume[:filesystem] = match[2].gsub('"', '')
            end
          end
          if conditions
            matched = true
            conditions.each do |key,value|
              unless volume[key] == value
                matched = false
                break
              end
            end
            results << volume if matched
          else
            results << volume
          end
        end
        results
      end
    end # VolumeManager

    class Shell

      # Overrides base Shell#uptime
      def uptime
        return ::File.read('/proc/uptime').split(/\s+/)[0].to_f rescue 0.0
      end

      # Overrides base Shell#booted_at
      def booted_at
        match = /btime ([0-9]+)/.match(::File.read('/proc/stat')) rescue nil
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
        execute('init 6 2>&1')
        true
      end

      # Overrides base Controller#shutdown
      def shutdown
        execute('init 0 2>&1')
        true
      end
    end # Controller

    class Installer

      # Does this machine have aptitude?
      #
      # @return [TrueClass|FalseClass] true if aptitude is available in the expected directory
      def aptitude?
        ::File.executable? '/usr/bin/apt-get'
      end
      
      # Does this machine have yum?
      #
      # @return [TrueClass|FalseClass] true if yum is available in the expected directory
      def yum?
        ::File.executable? '/usr/bin/yum'
      end
      
      # Does this machine have zypper?
      #
      # @return [TrueClass|FalseClass] true if zypper is available in the expected directory
      def zypper?
        ::File.executable? '/usr/bin/zypper'
      end
      
      # Overrides base Installer#install
      def install(packages)
        packages = Array(packages)
        return true if packages.empty?
        
        packages = packages.uniq.join(' ')

        if yum?
          command = "yum install -y #{packages} 2>&1"
          regex   = /No package (.*) available\./
        elsif aptitude?
          old_debian_frontend = ENV['DEBIAN_FRONTEND']
          ENV['DEBIAN_FRONTEND'] = 'noninteractive'
          command = "apt-get install -y #{packages} 2>&1"
          # note the error message for apt-get seems to have changed between
          # versions of aptitude.
          regex = /E: (Couldn't find package|Unable to locate package) (.*)/
        elsif zypper?
          command = "zypper --no-gpg-checks -n #{packages} 2>&1"
          regex   = /Package '(.*)' not found\./
        else
          raise PackageManagerNotFound,
                'No package manager binary (apt, yum, zypper) found in /usr/bin'
        end

        failed_packages = nil
        begin
          # TEAL FIX it's not clear from legacy implementation if having failed
          # packages consistently exits non-zero from all supported installers.
          # for that reason, also scan for failed packages on exit zero.
          failed_packages = scan_for_failed_packages(execute(command), regex)
        rescue ::RightScale::Platform::CommandError => e
          # command could fail for reasons other than failed packages (e.g. not
          # being sudo) but legacy code raised a specific error for failed
          # packages.
          failed_packages = scan_for_failed_packages(e.output_text, regex)
          raise if failed_packages.empty?
        ensure
          ENV['DEBIAN_FRONTEND'] = old_debian_frontend if aptitude?
        end
        unless failed_packages.empty?
          raise PackageNotFound,
                "The following packages were not available: #{failed_packages.join(', ')}"
        end
        true
      end

      private

      def scan_for_failed_packages(output_text, regex)
        @output = output_text
        failed_packages = []
        output_text.scan(regex) { |package| failed_packages << package.last }
        failed_packages
      end
    end # Installer

    private

    # Overrides base Platform#initialize_species
    def initialize_species
      # Use the lsb_release utility if it's available
      begin
        # TEAL FIX: not sure if we really need to check if --help succeeds or
        # if we would only need to call lsb_release -is but that was the legacy
        # behavior and retesting all supported flavors of Linux isn't trivial.
        execute('lsb_release --help >/dev/null 2>&1')
        @flavor   = execute('lsb_release -is', :raise_on_failure => false).strip.downcase
        @release  = execute('lsb_release -rs', :raise_on_failure => false).strip
        @codename = execute('lsb_release -cs', :raise_on_failure => false).strip
      rescue ::RightScale::Platform::CommandError
        if ::File.exist?(FEDORA_REL) && (match = FEDORA_SIG.match(::File.read(FEDORA_REL)))
          # Parse the fedora-release file if it exists
          @flavor   = 'fedora'
          @release  = match[1]
          @codename = match[2]
        else
          @flavor = @release = @codename = 'unknown'
        end
      end
      true
    end

  end # Platform
end # RightScale
