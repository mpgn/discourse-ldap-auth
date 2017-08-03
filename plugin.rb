# name:ldap 
# about: A plugin to provide ldap authentication. 
# version: 0.3.0
# authors: Jon Bake <jonmbake@gmail.com>
# modified by github.com/mpgn -> @mpgn_x64
# => add auto registration since we trust email from ldap db

enabled_site_setting :ldap_enabled

gem 'pyu-ruby-sasl', '0.0.3.3', require: false
gem 'rubyntlm', '0.3.4', require: false
gem 'net-ldap', '0.14.0'
gem 'omniauth-ldap', '1.0.5'

require 'yaml'

class LDAPAuthenticator < ::Auth::Authenticator
  def name
    'ldap'
  end

  def after_authenticate(auth_token)
    @name = auth_token.info[:name]
    @email = auth_token.info[:email]
    @username = auth_token.info[:nickname]
    result = Auth::Result.new
    result.name = @name
    result.username = @username
    result.email = @email
    result.user = User.find_by(username_lower: @username)
    if !result.user
      result.user = User.create(
        username: @username,
        name: @name,
        email: @email, 
        active: true)
    end
    result.omit_username = true
    result.email_valid = true
    return result
  end

  def register_middleware(omniauth)
    omniauth.configure{ |c| c.form_css = File.read(File.expand_path("../css/form.css", __FILE__)) }
    omniauth.provider :ldap,
      setup:  -> (env) {
        env["omniauth.strategy"].options.merge!(
          host: SiteSetting.ldap_hostname,
          port: SiteSetting.ldap_port,
          method: SiteSetting.ldap_method,
          base: SiteSetting.ldap_base,
          uid: SiteSetting.ldap_uid,
          # In 0.3.0, we fixed a typo in the ldap_bind_dn config name. This fallback will be removed in a future version.
          bind_dn: SiteSetting.ldap_bind_dn.presence || SiteSetting.try(:ldap_bind_db),
          password: SiteSetting.ldap_password,
          filter: SiteSetting.ldap_filter
        )
      }
  end

  private
  def auth_result(auth_info)
    case SiteSetting.ldap_user_create_mode
      when 'none'
        ldap_user = LDAPUser.new(auth_info)
        return ldap_user.account_exists? ? ldap_user.auth_result : fail_auth('User account does not exist.')
      when 'list'
        user_descriptions = load_user_descriptions
        return fail_auth('List of users must be provided when ldap_user_create_mode setting is set to \'list\'.') if user_descriptions.nil?
        #match on email
        match = user_descriptions.find { |ud|  auth_info[:email].casecmp(ud[:email]) == 0 }
        return fail_auth('User with email is not listed in LDAP user list.') if match.nil?
        match[:nickname] = match[:username] || auth_info[:nickname]
        match[:name] = match[:name] || auth_info[:name]
        return LDAPUser.new(match).auth_result
      when 'auto'
        return LDAPUser.new(auth_info).auth_result
      else
        return fail_auth('Invalid option for ldap_user_create_mode setting.')
    end
  end
  def fail_auth(reason)
    result = Auth::Result.new
    result.failed = true
    result.failed_reason = reason
    result
  end
  def load_user_descriptions
    file_path = "#{File.expand_path(File.dirname(__FILE__))}/ldap_users.yml"
    return nil unless File.exists?(file_path)
    return YAML.load_file(file_path)
  end
end

auth_provider title: 'Connexion LDAP',
  message: 'Se connecter avec vos identifiants LDAP',
  frame_width: 480,
  frame_height: 480,
  authenticator: LDAPAuthenticator.new

register_css <<CSS
  .btn.ldap {
    background-color: #517693;
  }
CSS
