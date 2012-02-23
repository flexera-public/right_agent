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

  # Boot, operation or decommission executable bundle, includes:
  # * RightScripts with associated packages, parameters and attachments
  # * Recipes with associated JSON
  # * Cookbook repositories with associated attributes
  # * Audit id
  # Recipes and RightScripts instantiations are interspersed and ordered into one collection
  # The instance agent can use the audit created by the core agent to audit messages
  # associated with the processing of the software repositories
  class ExecutableBundle

    include Serializable

    # (Array) Collection of RightScripts and chef recipes instantiations
    attr_accessor :executables

    # (Array) Chef cookbook repositories
    attr_accessor :cookbook_repositories

    # (Integer) ID of corresponding audit entry
    attr_accessor :audit_id

    # (Boolean) Whether a full or partial converge should be done
    # Note: Obsolete as of r_s_version 8, kept for backwards compatibility
    attr_accessor :full_converge

    # (Array) Chef cookbooks
    attr_accessor :cookbooks

    # (String) Repose server to use
    attr_accessor :repose_servers

    # (Hash):: collection of repos to be checked out on the instance
    #   :key (String):: the hash id (SHA) of the repository
    #  :value (Hash):: repo and cookbook detail
    #    :repo (Hash):: repo details
    #     {
    #       <Symbol> Type of repository: one of :git, :svn, :download or :local
    #         * :git denotes a 'git' repository that should be retrieved via 'git clone'
    #         * :svn denotes a 'svn' repository that should be retrieved via 'svn checkout'
    #         * :download denotes a tar ball that should be retrieved via HTTP GET (HTTPS if uri starts with https://)
    #         * :local denotes cookbook that is already local and doesn't need to be retrieved
    #       :repo_type => <Symbol>,
    #       <String> URL to repository (e.g. git://github.com/opscode/chef-repo.git)
    #       :url => <String>,
    #       <String> git commit or svn branch that should be used to retrieve repository
    #         Optional, use 'master' for git and 'trunk' for svn if tag is nil.
    #         Not used for raw repositories.
    #       :tag => <String>,
    #       <Array> Path to cookbooks inside repostory
    #         Optional (use location of repository as cookbook path if nil)
    #       :cookbooks_path => <Array>,
    #       <String> Private SSH key used to retrieve git repositories
    #         Optional, not used for svn and raw repositories.
    #       :ssh_key => <String>,
    #       <String> Username used to retrieve svn and raw repositories
    #         Optional, not used for git repositories.
    #       :username => <String>,
    #       <String> Password used to retrieve svn and raw repositories
    #         Optional, not used for git repositories.
    #       :password => <String>
    #     }
    #    :positions (Array):: List of CookbookPositions to be developed.  Represents the subset of cookbooks identified as the "dev cookbooks"
    attr_accessor :dev_cookbooks

    def initialize(*args)
      @executables           = args[0]
      @cookbook_repositories = args[1] if args.size > 1
      @audit_id              = args[2] if args.size > 2
      @full_converge         = args[3] if args.size > 3
      @cookbooks             = args[4] if args.size > 4
      @repose_servers        = args[5] if args.size > 5
      @dev_cookbooks         = args[6] if args.size > 6
      @thread_name           = args[7] if args.size > 7
    end

    # Array of serialized fields given to constructor
    def serialized_members
      [ @executables,
        @cookbook_repositories,
        @audit_id,
        @full_converge,
        @cookbooks,
        @repose_servers,
        @dev_cookbooks,
        @thread_name ]
    end

    # Human readable representation
    #
    # === Return
    # desc(String):: Auditable description
    def to_s
      desc = @executables.collect { |e| e.nickname }.join(', ') if @executables
      desc ||= 'empty bundle'
    end
  end
end
