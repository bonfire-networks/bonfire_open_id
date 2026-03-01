defmodule Bonfire.OpenID.Plugs.AuthRequired do
  use Bonfire.UI.Common.Web, :plug

  def require_auth(conn, opts) do
    with %{assigns: %{current_user: %{id: _}}} = conn <-
           Bonfire.OpenID.Plugs.Authorize.maybe_load_authorization(conn, opts) do
      conn
    else
      other ->
        debug(other, "Auth required plug failed to load authorization")
        raise Bonfire.Fail, :needs_login
    end
  end
end
