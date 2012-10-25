module RightScale
  # Mac OS specific implementation
  class Platform
    class Filesystem
      # Directory containing generated agent configuration files
      # @deprecated
      def cfg_dir
        warn "cfg_dir is deprecated; please use right_agent_cfg_dir"
        right_agent_cfg_dir
      end

      # RightScale state directory for the current platform
      # @deprecated
      def right_scale_state_dir
        warn "right_scale_state_dir is deprecated; please use either right_scale_static_state_dir or right_agent_dynamic_state_dir"
        right_scale_static_state_dir
      end

      # Directory containing generated agent configuration files
      def right_agent_cfg_dir
        '/var/lib/rightscale/right_agent'
      end

      # Static (time-invariant) state that is common to all RightScale apps/agents
      def right_scale_static_state_dir
        '/etc/rightscale.d'
      end
    end
  end
end
