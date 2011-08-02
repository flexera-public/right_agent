#!/bin/bash -e

#
# Example tool installer script for an_agent in RightScale environment
#
AGENT_TYPE=an_agent

#
# First figure out where this script lives, which lets us infer
# where the Ruby scripts live (parallel to this script).
#
FIXED_PATH_GUESS=/home/rails/right_net/current/${AGENT_TYPE}/scripts
ABSOLUTE_PATH_GUESS=`dirname $0`
if [ -e $FIXED_PATH_GUESS/install.sh ]
then
  SCRIPTS_DIR=$FIXED_PATH_GUESS
elif [ -e $ABSOLUTE_PATH_GUESS/install.sh ]
then
  pushd $ABSOLUTE_PATH_GUESS > /dev/null
  SCRIPTS_DIR=$PWD
  popd > /dev/null
else
  echo "Cannot determine path from $0"
  echo "Please invoke this script using its absolute path."
  exit 1
fi

#
# Next locate a Ruby interpreter
#
if [ ! -z `which ruby` ]
then
  RUBY_BIN=`which ruby`
elif [ ! -z $1 ]
then
  RUBY_BIN=$1
fi

if [ -z $RUBY_BIN ]
then
  echo "Can't locate Ruby interpreter! Run this script again and either:"
  echo " 1) ensure 'ruby' is in your path somewhere, or"
  echo " 2) supply the full path to 'ruby' as a cmd-line argument to this script"
  exit 1
fi

#
# Create scripts for running all of the binaries
#
echo Installing scripts from $SCRIPTS_DIR...

for script in rad rnac rlog rstat
do
  case "$script" in
    rad)   require="right_infrastructure_agent/scripts/infrastructure_agent_deployer"
           class=RightScale::InfrastructureAgentDeployer;;
    rnac)  require="right_infrastructure_agent/scripts/infrastructure_agent_controller"
           class=RightScale::InfrastructureAgentController;;
    rlog)  require="right_agent/scripts/log_level_manager"
           class=RightScale::LogLevelManager;;
    rstat) require="right_agent/scripts/stats_manager"
           class=RightScale::StatsManager;;
  esac
  echo Installing $script
  rm -f /usr/bin/$script
  cat > /usr/bin/$script <<EOF
#!/usr/bin/env ruby

# $script --help for usage information
#
# See $require.rb for additional information

require 'rubygems'
require File.join('$SCRIPTS_DIR', '..', '..', 'lib', 'bundler_support')
RightScale::BundlerSupport.activate
require '$require'

\$stdout.sync=true

$class.run
EOF
  chmod a+x /usr/bin/$script
done

echo Done.

