# @api private
#  Ensure ntp is configured (Scored)
#
# Description:
# ntp is a daemon which implements the Network Time Protocol (NTP). It is designed to
# synchronize system clocks across a variety of systems and use a source that is highly
# accurate. More information on NTP can be found at http://www.ntp.org. ntp can be
# configured to be a client and/or a server.
# This recommendation only applies if ntp is in use on the system.
#
# Rationale:
# If ntp is in use on the system proper configuration is vital to ensuring time synchronization
# is working properly.
#
# @summary  Ensure ntp is configured (Scored)
#
# @param enforced Should this rule be enforced
# @param time_servers Array of valid NTP Time servers
# @param time_sync Which NTP program to use
#
# @example
#   include secure_linux_cis::ensure_ntp_is_configured
class secure_linux_cis::rules::ensure_ntp_is_configured {
    if $secure_linux_cis::time_sync == 'ntp' {
      class { '::ntp':
        servers  => $secure_linux_cis::time_servers,
        restrict => [
          '-4 default kod nomodify notrap nopeer noquery',
          '-6 default kod nomodify notrap nopeer noquery',
        ],
      }
      case $facts['osfamily'] {
        'RedHat': {
          file { '/etc/sysconfig/ntpd':
            ensure  => file,
            owner   => 'root',
            group   => 'root',
            mode    => '0644',
            content => 'OPTIONS="-u ntp:ntp"',
          }
        }
        'Debian': {
          file_line { 'ntpuser':
            ensure  => present,
            path    => '/etc/init.d/ntp',
            line    => 'RUNASUSER=ntp',
            match   => '^RUNASUSER=',
            require => Class['::ntp']
          }
        }
        default: {
          warning ("NTP configuration is not supported on os family ${facts['osfamily']}.")
        }
      }
    }


#########Debugging
  if $secure_linux_cis_helper::activate_debug or lookup( secure_linux_cis_helper::activate_debug, undef, undef, false )  {
    $secure_linux_cis_params = {
      secure_linux_cis::motd => $secure_linux_cis::motd,
      secure_linux_cis::enforcement_level => $secure_linux_cis::enforcement_level,
      secure_linux_cis::profile_type => $secure_linux_cis::profile_type,
      secure_linux_cis::allow_users  => $secure_linux_cis::allow_users,
      secure_linux_cis::time_servers => $secure_linux_cis::time_servers,
      secure_linux_cis::lockout_time => $secure_linux_cis::lockout_time,
    }

    $secure_linux_cis_params.each | String $key,   $para | {
      $paravalue=pick_default( $para , '===undef===')
      notify{ "Under ${name}, secure_linux_cis_params: ${key} ":
          message => "Under ${name},   secure_linux_cis_params              ${key}=${paravalue}=",
        }
    }
  }
#########################


}
