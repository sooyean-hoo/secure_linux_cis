# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include secure_linux_cis::rules::ensure_inetd_is_not_installed
class secure_linux_cis::rules::ensure_inetd_is_not_installed(
    Boolean $enforced = true,
) {
  if $enforced {
    package { 'inetd':
      ensure => purged,
    }
  }
}