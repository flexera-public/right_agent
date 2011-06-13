# Copyright (c) 2009-2011 RightScale, Inc, All Rights Reserved Worldwide.
#
# THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO RIGHTSCALE
# AND CONSTITUTES A VALUABLE TRADE SECRET.  Any unauthorized use,
# reproduction, modification, or disclosure of this program is
# strictly prohibited.  Any use of this program by an authorized
# licensee is strictly subject to the terms and conditions,
# including confidentiality obligations, set forth in the applicable
# License Agreement between RightScale.com, Inc. and the licensee.

module RightScale

  class LoginPolicyFactory

    # Create LoginPolicy for given account, including all users that are authorized
    # to login, their public keys, etc. The policy is based on Permissions, UserCredentials
    # and Settings of the account and is uniform across all instances of the account.
    #
    # === Parameters
    # account(Account):: Account that login policy should be built for
    #
    # === Return
    # policy(RightScale::LoginPolicy) Policy specifying which users may login & some related metadata
    def self.policy_for_account(account)
      # Find all users who are allowed and able to do managed login. Simultaneously build some indices
      # of timestamps authorizing perms, which will be used presently to create the policy object.
      users = User.all( :select     => "`users`.*, `user_credentials`.public_value as cred_public_value, `user_credentials`.updated_at as cred_updated_at, `permissions`.updated_at as perm_updated_at, `permissions`.deleted_at as perm_deleted_at",
                        :joins      => [:user_credential, :permissions],
                        :conditions => ["permissions.id = (SELECT p.id FROM permissions p " +
                                                           "WHERE p.account_id = ?  " +
                                                           "AND p.user_id = users.id  " +
                                                           "AND p.role_id = ?  " +
                                                           "AND (p.deleted_at IS NULL OR p.deleted_at > ?) " +
                                                           "LIMIT 1) " +
                                          "AND user_credentials.public_value IS NOT NULL " +
                                          "AND user_credentials.public_value <> ''",
                                        account.id, Role['server_login'], Time.now.utc ])

      # Build the policy and its list of users
      timestamps_max = Time.at(0)
      policy = LoginPolicy.new
      policy.exclusive  = account.setting('managed_login_mandatory')
      policy.users = users.map do |u|
        timestamps_max = [timestamps_max, Time.parse(u.perm_updated_at), Time.parse(u.cred_updated_at)].max

        uuid        = Biz::ResourceUuidMixin.obfuscate_id(u.id)
        username    = "rs#{uuid.downcase}"
        public_keys = [u.cred_public_value]
        common_name = u.email
        superuser   = true
        expires_at  = u.perm_deleted_at.nil? ? nil : Time.parse(u.perm_deleted_at)

        # Post-process the public keys to make sure they are well-formed AND contain a comment
        # at the end of the line. Technically the comment is optional, but a bug in RightImage
        # 5.1.1 - 5.6 makes the comment mandatory else the instance has heinous problems
        # when trying to update its managed login policy.
        processed_keys = public_keys.map do |k|
          components = LoginPolicy.parse_public_key(k)
          if components
            components[3] ||= u.email
            next components.compact.join(' ')
          else
            next nil
          end
        end
        # In case there was some malformed or other weird key, remove its (nil) value
        processed_keys.compact!

        next LoginUser.new(uuid, username, nil, common_name, superuser, expires_at, processed_keys)
      end

      policy.created_at = timestamps_max

      return policy
    end

    # Create LoginPolicy for given instance, including all users that are authorized
    # to login, their public keys, etc. Currently this just delegates to #policy_for_account
    # since all instances of a given account have the same policy at a given time. This may
    # change in the future, however.
    #
    # === Parameters
    # instance(Ec2Instance):: Instance that login policy should be built for
    #
    # === Return
    # policy(RightScale::LoginPolicy) Policy specifying which users may login & some related metadata
    def self.policy_for_instance(instance, audit_id)
      policy = policy_for_account(instance.account)
      policy.audit_id = audit_id
      return policy      
    end

  end # LoginPolicyFactory

end # RightScale
