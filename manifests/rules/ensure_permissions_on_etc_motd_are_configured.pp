# @api private
#  Ensure permissions on /etc/motd are configured (Not Scored)
#
#
# Description:
# The contents of the /etc/motd file are displayed to users after login and function as a message of the day for authenticated users.
#
# @summary  Ensure permissions on /etc/motd are configured (Not Scored)
#
# @param enforced Should this rule be enforced
# @param banner Text of the motd, if $motd is empty
# @param motd Text of the motd
#
# @example
#   include secure_linux_cis::ensure_permissions_on_etc_motd_are_configured
class secure_linux_cis::rules::ensure_permissions_on_etc_motd_are_configured {
    unless $secure_linux_cis::motd and $secure_linux_cis::banner {
      $motd_real = $secure_linux_cis::banner
    }
    else {
      $motd_real = $secure_linux_cis::motd
    }
    file { '/etc/motd':
      ensure  => present,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => $motd_real,
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
