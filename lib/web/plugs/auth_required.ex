defmodule Bonfire.OpenID.Plugs.AuthRequired do
  use Bonfire.UI.Common.Web, :plug

  def require_auth(conn, _opts) do
    Bonfire.OpenID.Plugs.Authorize.maybe_load_authorization(conn) ||
      raise Bonfire.Fail, :needs_login
  end
end
